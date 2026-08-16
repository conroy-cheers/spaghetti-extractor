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
    _check_rooted_parametric_summaries,
    _check_target_induction,
    build_release_acceptance_receipt,
    build_structural_executable_receipt,
    load_policy_receipt,
    write_policy_receipt,
    _STRUCTURAL_AUXILIARY_ARTIFACTS,
    _STRUCTURAL_ARTIFACTS,
)
from spaghetti_extractor.components.formats import COMPONENT_RELEASE_GATE_V1_FORMAT


class CandidatePolicyGateTests(unittest.TestCase):
    def test_structural_gate_requires_checked_inductive_authority(self) -> None:
        self.assertEqual(
            _STRUCTURAL_AUXILIARY_ARTIFACTS,
            frozenset(
                {
                    "inductive_authority",
                    "parametric_summaries",
                    "target_certificates",
                }
            ),
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
        root_path = Path("root-closure")
        summary_path = Path("parametric-summaries")
        root_record = object()
        pairs = tuple(
            (summary_rows[index], summary_rows[index + 1])
            for index in range(0, len(summary_rows), 2)
        )
        records = tuple(object() for _ in pairs)
        readers = {
            root_path: SimpleNamespace(
                manifest=SimpleNamespace(artifact_kind="launch-root-closure-v3"),
                manifest_sha256="d" * 64,
                iter_records=lambda: iter((root_record,)),
            ),
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
                "LAUNCH_ROOT_CLOSURE_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(
                        value=SimpleNamespace(
                            reachable_unit_ids=reachable,
                            status="complete",
                            authorizing=True,
                        )
                    )
                ),
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
                root_closure=root_path,
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
        root_path = Path("root-closure")
        target_path = Path("target-certificates")
        authority_path = Path("inductive-authority")
        root_record = object()
        target_record = object()
        authority_records = tuple(object() for _ in authority_cutpoints)
        readers = {
            root_path: SimpleNamespace(
                manifest=SimpleNamespace(artifact_kind="launch-root-closure-v3"),
                manifest_sha256="a" * 64,
                iter_records=lambda: iter((root_record,)),
            ),
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
        root = SimpleNamespace(
            reachable_unit_ids=reachable_units,
            status="complete",
            authorizing=True,
        )
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
                "LAUNCH_ROOT_CLOSURE_CODEC_V3",
                SimpleNamespace(
                    read=lambda _record: SimpleNamespace(value=root)
                ),
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
                root_closure=root_path,
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
                "spaghetti_extractor.candidate.policy_gates._check_artifact_family",
                return_value=PolicyFamilyReceiptV1(
                    "isa_qualification", "complete", "c" * 64, 1, None
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
                "spaghetti_extractor.candidate.policy_gates._check_artifact_family",
                return_value=PolicyFamilyReceiptV1(
                    "isa_qualification", "complete", "c" * 64, 1, None
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
            "counts": {
                "portable_c": 1,
                "pinned_binary": 0,
                "machine_ir": 0,
                "external_environment": 0,
                "blocked": 0,
                "machine_ir_fallback_units": 0,
                "blocked_units": 0,
            },
            "issues": [],
            "policy": {
                "original_binary_executed": False,
                "handwritten_behavior_tests_required": False,
                "hybrid_allows_qualified_pinned_implementations": True,
                "portable_requires_no_pinned_or_machine_implementations": False,
            },
        }
        return {**core, "gate_sha256": canonical_sha256_v3(core)}

if __name__ == "__main__":
    unittest.main()
