from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.artifacts.io import write_artifact_bundle_v3
from spaghetti_extractor.candidate.policy_gates import (
    CandidatePolicyError,
    CandidatePolicyReceiptV1,
    PolicyFamilyReceiptV1,
    STRUCTURAL_EXECUTABLE_V1,
    _ArtifactFamily,
    _check_artifact_family,
    _check_rooted_artifact_family,
    _check_rooted_parametric_summaries,
    _check_target_induction,
    build_release_acceptance_receipt,
    build_structural_executable_receipt,
    load_policy_receipt,
    write_policy_receipt,
    _STRUCTURAL_AUXILIARY_ARTIFACTS,
    _STRUCTURAL_ARTIFACTS,
    _ROOTED_BEHAVIORAL_ARTIFACTS,
)
from spaghetti_extractor.candidate.authority.rooted_projection import (
    ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
    RootedBehavioralProjectionError,
    RootedBehavioralProjectionV1,
    derive_rooted_behavioral_projection_v1,
)
from spaghetti_extractor.components.formats import COMPONENT_RELEASE_GATE_V1_FORMAT


class CandidatePolicyGateTests(unittest.TestCase):
    @staticmethod
    def _projection(
        reachable: tuple[str, ...] = ("unit:root",),
    ) -> RootedBehavioralProjectionV1:
        core: dict[str, object] = {
            "format": ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
            "root_unit_ids": [reachable[0]],
            "reachable_unit_ids": list(reachable),
            "structural_unit_count": len(reachable) + 1,
            "bindings": {
                "root_closure_manifest_sha256": "a" * 64,
                "semantic_index_manifest_sha256": "b" * 64,
                "semantic_universe_sha256": "c" * 64,
            },
        }
        return RootedBehavioralProjectionV1.parse(
            {**core, "projection_sha256": canonical_sha256_v3(core)}
        )

    def test_structural_gate_requires_checked_inductive_authority(self) -> None:
        self.assertEqual(
            _STRUCTURAL_AUXILIARY_ARTIFACTS,
            frozenset(
                {
                    "inductive_authority",
                    "parametric_summaries",
                    "root_closure",
                }
            ),
        )

    def test_rooted_projection_rejects_stale_reachable_scope(self) -> None:
        payload = self._projection().to_payload()
        payload["reachable_unit_ids"] = ["unit:other"]

        with self.assertRaisesRegex(
            RootedBehavioralProjectionError, "unit inventories|digest is stale"
        ):
            RootedBehavioralProjectionV1.parse(payload)

    def test_rooted_projection_preserves_the_larger_structural_universe(self) -> None:
        root_record = object()
        semantic_records = (object(), object())
        readers = {
            Path("root-closure"): SimpleNamespace(
                manifest=SimpleNamespace(artifact_kind="launch-root-closure-v3"),
                manifest_sha256="a" * 64,
                iter_records=lambda: iter((root_record,)),
            ),
            Path("semantic-index"): SimpleNamespace(
                manifest=SimpleNamespace(artifact_kind="semantic-index-v3"),
                manifest_sha256="b" * 64,
                iter_records=lambda: iter(semantic_records),
            ),
        }
        semantic_values = iter(
            (
                SimpleNamespace(record_id="unit:root", unit_status="qualified"),
                SimpleNamespace(
                    record_id="unit:unreachable", unit_status="incomplete"
                ),
            )
        )
        with (
            patch(
                "spaghetti_extractor.candidate.authority.rooted_projection."
                "open_artifact_reader_v3",
                side_effect=lambda path: readers[path],
            ),
            patch(
                "spaghetti_extractor.candidate.authority.rooted_projection."
                "LAUNCH_ROOT_CLOSURE_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(
                        value=SimpleNamespace(
                            status="complete",
                            authorizing=True,
                            frontier_ids=(),
                            root_unit_ids=("unit:root",),
                            reachable_unit_ids=("unit:root",),
                            edges=(),
                        )
                    )
                ),
            ),
            patch(
                "spaghetti_extractor.candidate.authority.rooted_projection."
                "SEMANTIC_INDEX_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(
                        value=next(semantic_values)
                    )
                ),
            ),
            patch(
                "spaghetti_extractor.candidate.authority.rooted_projection."
                "semantic_universe_sha256_v3",
                return_value="c" * 64,
            ),
        ):
            projection = derive_rooted_behavioral_projection_v1(
                root_closure=Path("root-closure"),
                semantic_index=Path("semantic-index"),
            )

        self.assertEqual(projection.reachable_unit_ids, ("unit:root",))
        self.assertEqual(projection.structural_unit_count, 2)
        self.assertEqual(
            set(_ROOTED_BEHAVIORAL_ARTIFACTS),
            {
                "callbacks",
                "exceptional_transitions",
                "external_sites",
                "target_certificates",
            },
        )

    def test_rooted_parametric_summaries_require_exact_complete_coverage(
        self,
    ) -> None:
        complete = self._rooted_summary_receipt(
            reachable=("unit:a",),
            summary_rows=(("unit:a",), True),
        )
        unreachable_incomplete = self._rooted_summary_receipt(
            reachable=("unit:a",),
            summary_rows=(("unit:a",), True, ("unit:z",), False),
        )
        missing = self._rooted_summary_receipt(
            reachable=("unit:a", "unit:b"),
            summary_rows=(("unit:a",), True),
        )
        ambiguous = self._rooted_summary_receipt(
            reachable=("unit:a",),
            summary_rows=(("unit:a",), True, ("unit:a",), True),
        )

        self.assertEqual(complete.status, "complete")
        self.assertEqual(unreachable_incomplete.status, "complete")
        self.assertEqual(missing.status, "incomplete")
        self.assertEqual(ambiguous.status, "incomplete")

    @staticmethod
    def _rooted_summary_receipt(
        *,
        reachable: tuple[str, ...],
        summary_rows: tuple[object, ...],
    ) -> PolicyFamilyReceiptV1:
        summary_path = Path("parametric-summaries")
        pairs = tuple(
            (summary_rows[index], summary_rows[index + 1])
            for index in range(0, len(summary_rows), 2)
        )
        records = tuple(object() for _ in pairs)
        readers = {
            summary_path: SimpleNamespace(
                manifest=SimpleNamespace(
                    artifact_kind="parametric-scc-summaries-v3"
                ),
                manifest_sha256="e" * 64,
                iter_records=lambda: iter(records),
            ),
        }
        summaries = iter(
            SimpleNamespace(
                member_unit_ids=members,
                status="complete" if checked else "incomplete",
                authorizing=checked,
            )
            for members, checked in pairs
        )
        with (
            patch(
                "spaghetti_extractor.candidate.policy_gates.open_artifact_reader_v3",
                side_effect=lambda path: readers[path],
            ),
            patch(
                "spaghetti_extractor.candidate.policy_gates."
                "PARAMETRIC_SCC_SUMMARY_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(value=next(summaries))
                ),
            ),
        ):
            return _check_rooted_parametric_summaries(
                projection=CandidatePolicyGateTests._projection(reachable),
                parametric_summaries=summary_path,
            )

    def test_target_induction_checks_only_rooted_consumers(self) -> None:
        receipt = self._target_induction_receipt(
            reachable_units=("unit:root",),
            source_unit_id="unit:unreachable",
            required_cutpoint="unit:cutpoint",
            authority_cutpoints=(),
        )

        self.assertEqual(receipt.status, "complete")
        self.assertEqual(receipt.record_count, 0)

    def test_target_induction_requires_one_checked_certificate(self) -> None:
        complete = self._target_induction_receipt(
            reachable_units=("unit:root",),
            source_unit_id="unit:root",
            required_cutpoint="unit:cutpoint",
            authority_cutpoints=("unit:cutpoint",),
        )
        missing = self._target_induction_receipt(
            reachable_units=("unit:root",),
            source_unit_id="unit:root",
            required_cutpoint="unit:cutpoint",
            authority_cutpoints=(),
        )
        ambiguous = self._target_induction_receipt(
            reachable_units=("unit:root",),
            source_unit_id="unit:root",
            required_cutpoint="unit:cutpoint",
            authority_cutpoints=("unit:cutpoint", "unit:cutpoint"),
        )

        self.assertEqual(complete.status, "complete")
        self.assertEqual(complete.record_count, 1)
        self.assertEqual(missing.status, "incomplete")
        self.assertIn("lack one exact", str(missing.blocker))
        self.assertEqual(ambiguous.status, "incomplete")

    @staticmethod
    def _target_induction_receipt(
        *,
        reachable_units: tuple[str, ...],
        source_unit_id: str,
        required_cutpoint: str,
        authority_cutpoints: tuple[str, ...],
    ) -> PolicyFamilyReceiptV1:
        target_path = Path("target-certificates")
        authority_path = Path("inductive-authority")
        target_record = SimpleNamespace(record_id=source_unit_id)
        authority_records = tuple(object() for _ in authority_cutpoints)
        readers = {
            target_path: SimpleNamespace(
                manifest=SimpleNamespace(
                    artifact_kind="indirect-target-certificates-v3"
                ),
                manifest_sha256="b" * 64,
                iter_records=lambda: iter((target_record,)),
            ),
            authority_path: SimpleNamespace(
                manifest=SimpleNamespace(artifact_kind="inductive-authority-v3"),
                manifest_sha256="c" * 64,
                iter_records=lambda: iter(authority_records),
            ),
        }
        dependency = SimpleNamespace(
            input_name="inductive_inputs", record_id=required_cutpoint
        )
        certificate = SimpleNamespace(
            authorizing=True,
            evaluation_method="inductive_finite_values",
            dependencies=(dependency,),
        )
        unit = SimpleNamespace(
            source_unit_id=source_unit_id, certificates=(certificate,)
        )
        authority_values = iter(
            SimpleNamespace(
                authorizing=True,
                status="complete",
                body=SimpleNamespace(to_value=lambda: {}),
            )
            for _ in authority_records
        )
        bodies = iter(
            SimpleNamespace(
                certificate_reports=(
                    SimpleNamespace(
                        status="complete", member_cutpoints=(cutpoint,)
                    ),
                )
            )
            for cutpoint in authority_cutpoints
        )
        with (
            patch(
                "spaghetti_extractor.candidate.policy_gates.open_artifact_reader_v3",
                side_effect=lambda path: readers[path],
            ),
            patch(
                "spaghetti_extractor.candidate.policy_gates."
                "INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(value=unit)
                ),
            ),
            patch(
                "spaghetti_extractor.candidate.policy_gates."
                "INDUCTIVE_AUTHORITY_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(
                        value=next(authority_values)
                    )
                ),
            ),
            patch(
                "spaghetti_extractor.candidate.policy_gates."
                "InductiveAuthorityBodyV3.parse",
                side_effect=lambda _value: next(bodies),
            ),
        ):
            return _check_target_induction(
                projection=CandidatePolicyGateTests._projection(
                    reachable_units
                ),
                target_certificates=target_path,
                inductive_authority=authority_path,
            )

    def test_structural_family_reader_accepts_aggregate_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shard = root / "shard"
            ArtifactSetWriterV3(
                artifact_kind="fixture-family-v3", bindings=()
            ).write(
                shard,
                [ArtifactRecordV3.create("unit:one", {"status": "complete"})],
            )
            bundle = root / "bundle"
            write_artifact_bundle_v3(
                bundle,
                (shard,),
                ("unit:one",),
                expected_kind="fixture-family-v3",
            )

            receipt = _check_artifact_family(
                "fixture",
                bundle,
                _ArtifactFamily(
                    "fixture-family-v3",
                    lambda record: SimpleNamespace(
                        status=record.value.to_value()["status"],
                        authorizing=True,
                    ),
                    lambda value: value.status == "complete" and value.authorizing,
                ),
            )

        self.assertEqual(receipt.status, "complete")
        self.assertEqual(receipt.record_count, 1)

    def test_rooted_behavioral_family_ignores_unreachable_blockers(self) -> None:
        path = Path("rooted-family")
        records = (
            ArtifactRecordV3.create("unit:root", {"status": "complete"}),
            ArtifactRecordV3.create("unit:unreachable", {"status": "incomplete"}),
        )
        reader = SimpleNamespace(
            manifest=SimpleNamespace(artifact_kind="fixture-family-v3"),
            manifest_sha256="d" * 64,
            iter_records=lambda: iter(records),
        )
        specification = _ArtifactFamily(
            "fixture-family-v3",
            lambda record: SimpleNamespace(
                record_id=record.record_id,
                status=record.value.to_value()["status"],
                authorizing=record.value.to_value()["status"] == "complete",
            ),
            lambda value: value.status == "complete" and value.authorizing,
        )
        with patch(
            "spaghetti_extractor.candidate.policy_gates.open_artifact_reader_v3",
            return_value=reader,
        ):
            accepted = _check_rooted_artifact_family(
                "rooted_behavior_fixture",
                path,
                specification,
                self._projection(),
            )
            blocked = _check_rooted_artifact_family(
                "rooted_behavior_fixture",
                path,
                specification,
                self._projection(("unit:root", "unit:unreachable")),
            )

        self.assertEqual(accepted.status, "complete")
        self.assertEqual(accepted.record_count, 1)
        self.assertEqual(blocked.status, "incomplete")
        self.assertIn("root-reachable", str(blocked.blocker))

    def test_round_trips_complete_structural_receipt(self) -> None:
        family = PolicyFamilyReceiptV1(
            "fallback_execution", "complete", "a" * 64, 3, None
        )
        bindings = {
            "activation_plan_sha256": "b" * 64,
            "machine_ir_manifest_sha256": "c" * 64,
            "machine_ir_sha256": "d" * 64,
            "pe_sha256": "e" * 64,
        }
        core = {
            "format": STRUCTURAL_EXECUTABLE_V1,
            "status": "complete",
            "executable": True,
            "release_accepted": False,
            "bindings": bindings,
            "families": [family.to_payload()],
        }
        receipt = CandidatePolicyReceiptV1(
            format=STRUCTURAL_EXECUTABLE_V1,
            status="complete",
            executable=True,
            release_accepted=False,
            bindings=bindings,
            families=(family,),
            receipt_sha256=canonical_sha256_v3(core),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "structural-executable.json"
            write_policy_receipt(path, receipt)
            observed = load_policy_receipt(path)
        self.assertEqual(observed, receipt)

    def test_corrupted_family_status_fails_closed(self) -> None:
        family = {
            "id": "fallback_execution",
            "status": "complete",
            "input_sha256": "a" * 64,
            "record_count": 1,
            "blocker": "not actually complete",
        }
        core = {
            "format": STRUCTURAL_EXECUTABLE_V1,
            "status": "complete",
            "executable": True,
            "release_accepted": False,
            "bindings": {},
            "families": [family],
        }
        payload = {**core, "receipt_sha256": canonical_sha256_v3(core)}
        with self.assertRaisesRegex(CandidatePolicyError, "blocker contradicts"):
            load_policy_receipt(payload)

    def test_structural_builder_requires_exact_family_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fallback = root / "fallback.json"
            activation = root / "activation.json"
            machine = root / "machine.jsonl"
            manifest = root / "manifest.json"
            for path in (fallback, activation, machine, manifest):
                path.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                CandidatePolicyError, "artifact families differ"
            ):
                build_structural_executable_receipt(
                    artifacts={},
                    fallback_capability_analysis=fallback,
                    activation_plan=activation,
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                    rooted_projection={},
                )

    def test_receipt_directory_must_be_unambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.json").write_text("{}", encoding="ascii")
            (root / "b.json").write_text("{}", encoding="ascii")
            with self.assertRaisesRegex(CandidatePolicyError, "exactly one"):
                load_policy_receipt(root)

    def test_release_does_not_require_candidate_only_tests(self) -> None:
        structural = self._structural_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            candidate.write_bytes(b"candidate")
            with patch(
                "spaghetti_extractor.candidate.policy_gates._check_rooted_artifact_family",
                return_value=PolicyFamilyReceiptV1(
                    "rooted_behavior_isa_qualification",
                    "complete",
                    "c" * 64,
                    1,
                    None,
                ),
            ):
                receipt = build_release_acceptance_receipt(
                    structural_receipt=structural,
                    isa_qualification=root,
                    candidate_binary=candidate,
                    component_release_gate=self._component_release_gate(),
                )

        self.assertEqual(receipt.status, "complete")
        self.assertTrue(receipt.executable)
        self.assertTrue(receipt.release_accepted)
        self.assertNotIn("candidate_tests", {row.identity for row in receipt.families})

    def test_release_reports_component_gate_for_another_activation(self) -> None:
        structural = self._structural_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            candidate.write_bytes(b"candidate")
            with patch(
                "spaghetti_extractor.candidate.policy_gates._check_rooted_artifact_family",
                return_value=PolicyFamilyReceiptV1(
                    "rooted_behavior_isa_qualification",
                    "complete",
                    "c" * 64,
                    1,
                    None,
                ),
            ):
                receipt = build_release_acceptance_receipt(
                    structural_receipt=structural,
                    isa_qualification=root,
                    candidate_binary=candidate,
                    component_release_gate=self._component_release_gate(
                        activation_plan_sha256="e" * 64
                    ),
                )

        family = next(
            row
            for row in receipt.families
            if row.identity == "component_contract_closure"
        )
        self.assertEqual(family.status, "incomplete")
        self.assertIn("another activation plan", str(family.blocker))

    @staticmethod
    def _structural_receipt(
        *, component_authority_receipts: dict[str, str] | None = None
    ) -> dict[str, object]:
        family = PolicyFamilyReceiptV1(
            "fallback_execution", "complete", "a" * 64, 1, None
        )
        core = {
            "format": STRUCTURAL_EXECUTABLE_V1,
            "status": "complete",
            "executable": True,
            "release_accepted": False,
            "bindings": {
                "pe_sha256": "b" * 64,
                "activation_plan_sha256": "d" * 64,
                "component_authority_receipts": component_authority_receipts or {},
                "rooted_behavioral_projection": (
                    CandidatePolicyGateTests._projection().to_payload()
                ),
            },
            "families": [family.to_payload()],
        }
        return {**core, "receipt_sha256": canonical_sha256_v3(core)}

    @staticmethod
    def _component_release_gate(
        *, activation_plan_sha256: str = "d" * 64
    ) -> dict[str, object]:
        core: dict[str, object] = {
            "format": COMPONENT_RELEASE_GATE_V1_FORMAT,
            "mode": "hybrid",
            "status": "ready",
            "ready": True,
            "graph_sha256": "f" * 64,
            "activation_plan_sha256": activation_plan_sha256,
            "rooted_behavioral_projection_sha256": (
                CandidatePolicyGateTests._projection().projection_sha256
            ),
            "counts": {
                "portable_c": 1,
                "pinned_binary": 0,
                "machine_ir": 0,
                "external_environment": 0,
                "blocked": 0,
                "machine_ir_fallback_units": 0,
                "root_reachable_units": 1,
                "root_reachable_machine_ir_fallback_units": 0,
                "unreachable_machine_ir_fallback_units": 0,
                "blocked_units": 0,
            },
            "issues": [],
            "policy": {
                "original_binary_executed": False,
                "handwritten_behavior_tests_required": False,
                "hybrid_allows_qualified_pinned_implementations": True,
                "portable_requires_no_pinned_implementations": False,
                "portable_requires_no_root_reachable_machine_ir_fallback": False,
            },
        }
        return {**core, "gate_sha256": canonical_sha256_v3(core)}

if __name__ == "__main__":
    unittest.main()
