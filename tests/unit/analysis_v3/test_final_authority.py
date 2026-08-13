from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3.callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
    CALLBACK_AUTHORITY_CODEC_V3,
    CallbackAuthorityRecordV3,
)
from spaghetti_extractor.analysis_v3.exceptional_transitions import (
    EXCEPTIONAL_TRANSITION_CODEC_V3,
    EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
    ExceptionalTransitionRecordV3,
)
from spaghetti_extractor.analysis_v3.external_sites import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
)
from spaghetti_extractor.analysis_v3.fallback_coverage import (
    FALLBACK_COVERAGE_ARTIFACT_KIND_V3,
    FALLBACK_COVERAGE_PHASE_V3,
    IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
    IMPLEMENTATION_CAPABILITY_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.final_authority import (
    FINAL_AUTHORITY_CODEC_V3,
    FINAL_AUTHORITY_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.inductive import (
    INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
    INDUCTIVE_AUTHORITY_CODEC_V3,
    InductiveAuthorityBodyV3,
    InductiveAuthorityRecordV3,
    InductiveCertificateReportV3,
    InductiveIssueV3,
)
from spaghetti_extractor.analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_EVIDENCE_CODEC_V3,
    ISA_QUALIFICATION_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.authority_common import PrimaryBlockerV3
from spaghetti_extractor.analysis_v3.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    LaunchRootClosureV3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    RecordDependencyV3,
)
from spaghetti_extractor.phase_framework_v3 import PhaseFrameworkV3Error
from tests.unit.analysis_v3.test_fallback_coverage import _capability
from tests.unit.analysis_v3.test_isa_qualification import (
    BINDING,
    _base_inputs,
    _evidence,
    _write,
)


class FinalAuthorityV3Tests(unittest.TestCase):
    def _chain(self, root: Path) -> dict[str, Path]:
        exact_path, semantic_path, closure_path, exact = _base_inputs(root)
        evidence = _evidence(exact)
        evidence_path = _write(
            root / "isa-evidence",
            ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
            (
                ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(
                    evidence.record_id, evidence
                ),
            ),
        )
        isa_path = ISA_QUALIFICATION_PHASE_V3.run(
            output_directory=root / "isa",
            inputs={
                "isa_evidence": evidence_path,
                "root_closure": closure_path,
                "semantic_index": semantic_path,
            },
            bindings=(BINDING,),
        ).output_directory
        capability = _capability(exact)
        capability_path = _write(
            root / "capabilities",
            IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
            (
                IMPLEMENTATION_CAPABILITY_CODEC_V3.write(
                    capability.record_id, capability
                ),
            ),
        )
        fallback_path = FALLBACK_COVERAGE_PHASE_V3.run(
            output_directory=root / "fallback",
            inputs={
                "implementation_capabilities": capability_path,
                "isa_qualification": isa_path,
                "semantic_index": semantic_path,
            },
            bindings=(BINDING,),
        ).output_directory

        external = CanonicalExternalSiteRecordV3(
            record_id=exact.unit_id,
            unit_sha256=exact.unit_sha256,
            status="complete",
            authorizing=True,
            sites=(),
            primary_blocker=None,
            dependencies=(),
        )
        external_path = _write(
            root / "external-sites",
            CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
            (CANONICAL_EXTERNAL_SITE_CODEC_V3.write(exact.unit_id, external),),
        )
        callbacks = CallbackAuthorityRecordV3(
            record_id=exact.unit_id,
            unit_sha256=exact.unit_sha256,
            status="complete",
            authorizing=True,
            callbacks=(),
            primary_blocker=None,
            dependencies=(),
        )
        callbacks_path = _write(
            root / "callbacks",
            CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
            (CALLBACK_AUTHORITY_CODEC_V3.write(exact.unit_id, callbacks),),
        )
        exceptions = ExceptionalTransitionRecordV3(
            record_id=exact.unit_id,
            unit_sha256=exact.unit_sha256,
            status="complete",
            authorizing=True,
            reachable=True,
            transitions=(),
            primary_blocker=None,
            dependencies=(),
        )
        exceptions_path = _write(
            root / "exceptions",
            EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
            (EXCEPTIONAL_TRANSITION_CODEC_V3.write(exact.unit_id, exceptions),),
        )

        report = InductiveCertificateReportV3.create(
            status="complete",
            member_cutpoints=(exact.unit_id,),
            transition_summary_ids=("transition-summary:fixture",),
            initiation_witnesses=(),
            preservation_witnesses=(),
            target_witnesses=(),
            checked_export_ids=(),
            issues=(),
        )
        body = InductiveAuthorityBodyV3.create(
            status="complete",
            authorizing=True,
            profile_sha256="c" * 64,
            binary_pe_sha256=BINDING.sha256,
            memory_version_graph_id="memory-version-graph:fixture",
            transition_summary_ids=("transition-summary:fixture",),
            root_unit_ids=(exact.unit_id,),
            certificate_reports=(report,),
            checked_exports=(),
            dependency_discharges=(),
            issues=(),
            structural_unit_count=1,
            reachable_unit_count=1,
        )
        inductive = InductiveAuthorityRecordV3(
            record_id="scc-v3:fixture",
            record_kind="scc_authority",
            authority_set_id=body.authority_id,
            status="complete",
            authorizing=True,
            body=CanonicalValueV3.of(body.to_payload()),
        )
        inductive_path = root / "inductive"
        ArtifactSetWriterV3(
            artifact_kind=INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
            bindings=(BINDING,),
            dependencies=(
                ArtifactSetReaderV3(semantic_path).dependency_binding(
                    "semantic_index"
                ),
            ),
        ).write(
            inductive_path,
            (
                INDUCTIVE_AUTHORITY_CODEC_V3.write(
                    inductive.record_id,
                    inductive,
                    dependencies=(
                        RecordDependencyV3("semantic_index", exact.unit_id),
                    ),
                ),
            ),
        )
        return {
            "callbacks": callbacks_path,
            "exceptional_transitions": exceptions_path,
            "external_sites": external_path,
            "fallback_coverage": fallback_path,
            "inductive_authority": inductive_path,
            "isa_qualification": isa_path,
            "root_closure": closure_path,
            "semantic_index": semantic_path,
        }

    def _run_final(self, root: Path, inputs: dict[str, Path]):
        output = FINAL_AUTHORITY_PHASE_V3.run(
            output_directory=root,
            inputs=inputs,
            bindings=(BINDING,),
        ).output_directory
        records = tuple(ArtifactSetReaderV3(output).iter_records())
        self.assertEqual(len(records), 1)
        return FINAL_AUTHORITY_CODEC_V3.read(records[0]).value

    def test_positive_v3_chain_authorizes_candidate_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._chain(root / "chain")
            checked = self._run_final(root / "final", inputs)
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            self.assertEqual(len(checked.families), 8)
            self.assertEqual(
                {row.input_name for row in checked.families}, set(inputs)
            )
            self.assertNotIn(
                "authority_bundle",
                FINAL_AUTHORITY_CODEC_V3.encode(checked),
            )

    def test_noncomplete_family_rejects_final_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._chain(root / "chain")
            fallback_records = tuple(
                ArtifactRecordV3.create(
                    row.record_id, row.value.to_value()
                )
                for row in ArtifactSetReaderV3(
                    inputs["fallback_coverage"]
                ).iter_records()
            )
            inputs["fallback_coverage"] = _write(
                root / "incomplete-fallback",
                FALLBACK_COVERAGE_ARTIFACT_KIND_V3,
                fallback_records,
                status="incomplete",
            )
            checked = self._run_final(root / "rejected", inputs)
            self.assertEqual(checked.status, "incomplete")
            self.assertFalse(checked.authorizing)
            self.assertEqual(
                checked.primary_blocker.code,
                "authority_family_artifact_not_complete",
            )

    def test_root_frontier_remains_incomplete_not_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._chain(root / "chain")
            closure_reader = ArtifactSetReaderV3(inputs["root_closure"])
            source = next(closure_reader.iter_records())
            closure = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(source).value
            incomplete = LaunchRootClosureV3(
                record_id=closure.record_id,
                status="incomplete",
                authorizing=False,
                submitted_root_ids=closure.submitted_root_ids,
                admitted_root_ids=closure.admitted_root_ids,
                reachable_unit_ids=closure.reachable_unit_ids,
                edges=closure.edges,
                frontier_ids=("indirect-exit:fixture",),
                primary_blocker=PrimaryBlockerV3(
                    "incomplete", "reachable_structural_frontier"
                ),
                dependencies=closure.dependencies,
            )
            incomplete_path = root / "incomplete-root-closure"
            ArtifactSetWriterV3(
                artifact_kind=LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
                bindings=(BINDING,),
                dependencies=closure_reader.manifest.dependencies,
                status="incomplete",
            ).write(
                incomplete_path,
                (
                    LAUNCH_ROOT_CLOSURE_CODEC_V3.write(
                        incomplete.record_id,
                        incomplete,
                    ),
                ),
            )
            inputs["root_closure"] = incomplete_path

            checked = self._run_final(root / "incomplete-final", inputs)

            self.assertEqual(checked.status, "incomplete")
            self.assertFalse(checked.authorizing)
            self.assertNotEqual(
                checked.primary_blocker.code,
                "root_closure_inventory_mismatch",
            )

    def test_incomplete_inductive_record_may_omit_binary_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._chain(root / "chain")
            semantic_record = next(
                ArtifactSetReaderV3(inputs["semantic_index"]).iter_records()
            )
            body = InductiveAuthorityBodyV3.create(
                status="incomplete",
                authorizing=False,
                profile_sha256=None,
                binary_pe_sha256=None,
                memory_version_graph_id=None,
                transition_summary_ids=(),
                root_unit_ids=(),
                certificate_reports=(),
                checked_exports=(),
                dependency_discharges=(),
                issues=(
                    InductiveIssueV3(
                        "incomplete",
                        "inductive_config_missing",
                        "scc-v3:fixture",
                    ),
                ),
                structural_unit_count=1,
                reachable_unit_count=0,
            )
            inductive = InductiveAuthorityRecordV3(
                record_id="scc-v3:fixture",
                record_kind="scc_authority",
                authority_set_id=body.authority_id,
                status="incomplete",
                authorizing=False,
                body=CanonicalValueV3.of(body.to_payload()),
            )
            inductive_path = root / "incomplete-inductive"
            ArtifactSetWriterV3(
                artifact_kind=INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
                bindings=(BINDING,),
                dependencies=(
                    ArtifactSetReaderV3(inputs["semantic_index"]).dependency_binding(
                        "semantic_index"
                    ),
                ),
            ).write(
                inductive_path,
                (
                    INDUCTIVE_AUTHORITY_CODEC_V3.write(
                        inductive.record_id,
                        inductive,
                        dependencies=(
                            RecordDependencyV3(
                                "semantic_index", semantic_record.record_id
                            ),
                        ),
                    ),
                ),
            )
            inputs["inductive_authority"] = inductive_path

            checked = self._run_final(root / "rejected-inductive", inputs)

            self.assertEqual(checked.status, "incomplete")
            self.assertFalse(checked.authorizing)
            self.assertEqual(
                checked.primary_blocker.code,
                "inductive_authority_not_complete",
            )

    def test_phase_contract_rejects_v2_bundle_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._chain(root / "chain")
            inputs["inductive_authority"] = _write(
                root / "v2-bundle",
                "authority-bundle-v2",
                (
                    ArtifactRecordV3.create(
                        "bundle:v2",
                        {"status": "complete", "authorizes": True},
                    ),
                ),
            )
            with self.assertRaisesRegex(
                PhaseFrameworkV3Error, "phase_input_kind_mismatch"
            ):
                FINAL_AUTHORITY_PHASE_V3.run(
                    output_directory=root / "wrong-kind",
                    inputs=inputs,
                    bindings=(BINDING,),
                )


if __name__ == "__main__":
    unittest.main()
