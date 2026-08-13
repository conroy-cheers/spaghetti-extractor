from __future__ import annotations

import dataclasses
import json
import unittest

from spaghetti_extractor.authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    UnitBinding,
)
from spaghetti_extractor.implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    CompletionStatusV2,
    ImplementationLedgerV2,
    ImplementationOwnerKindV2,
    ImplementationOwnerV2,
    UnitOwnershipRecordV2,
)
from spaghetti_extractor.lift_completion_receipt_v2 import (
    CandidateIdentityV2,
    CandidatePlatformV2,
    CompletionEvidenceV2,
    FinalAuthorityEvidenceV2,
    LiftCompletionReceiptV2,
    ValidationEvidenceV2,
)


def _digest(character: str) -> str:
    return character * 64


def _artifact(kind: str, name: str, character: str) -> ArtifactIdentityV2:
    return ArtifactIdentityV2(kind, name, _digest(character))


def _binary() -> BinaryBinding:
    return BinaryBinding(_digest("a"), _digest("b"))


def _unit(unit_id: str, start: int, character: str) -> UnitBinding:
    return UnitBinding(
        binary=_binary(),
        unit_id=unit_id,
        rva_start=start,
        rva_end=start + 16,
        unit_sha256=_digest(character),
        instruction_bytes_sha256=_digest(character),
    )


def _final(
    status: CompletionStatusV2 = CompletionStatusV2.COMPLETE,
    *,
    authorizing: bool = True,
    pe_sha256: str | None = None,
) -> FinalAuthorityEvidenceV2:
    return FinalAuthorityEvidenceV2(
        identity=_artifact("final-authority-v3", "final", "c"),
        status=status,
        authorizing=authorizing,
        original_pe_sha256=pe_sha256 or _binary().pe_sha256,
    )


def _fallback(
    status: CompletionStatusV2 = CompletionStatusV2.COMPLETE,
) -> CompletionEvidenceV2:
    return CompletionEvidenceV2(
        _artifact("fallback-coverage-v3", "fallback", "d"),
        status,
    )


def _runtime(
    status: CompletionStatusV2 = CompletionStatusV2.COMPLETE,
) -> CompletionEvidenceV2:
    return CompletionEvidenceV2(
        _artifact("runtime-lock-v1", "runtime", "e"),
        status,
    )


def _owner(
    kind: ImplementationOwnerKindV2,
    name: str,
    qualification: ArtifactIdentityV2,
    character: str,
) -> ImplementationOwnerV2:
    return ImplementationOwnerV2(
        kind,
        _artifact("implementation", name, character),
        qualification,
    )


def _static_ledger(fallback: CompletionEvidenceV2) -> ImplementationLedgerV2:
    unit = _unit("fallback-unit", 0x1000, "1")
    return ImplementationLedgerV2.create(
        profile=CompletionProfileV2.STATIC_BASELINE,
        binary=_binary(),
        structural_units=[unit],
        ownership_records=[
            UnitOwnershipRecordV2.create(
                owner=_owner(
                    ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                    "fallback-implementation",
                    fallback.identity,
                    "2",
                ),
                units=[unit],
            )
        ],
    )


def _portable_materials(
    profile: CompletionProfileV2 = CompletionProfileV2.PORTABLE_APPLICATION,
) -> tuple[
    ImplementationLedgerV2,
    CompletionEvidenceV2,
    CompletionEvidenceV2,
]:
    source = CompletionEvidenceV2(
        _artifact("source-qualification-v1", "source", "3"),
        CompletionStatusV2.COMPLETE,
    )
    library = CompletionEvidenceV2(
        _artifact("library-qualification-v1", "library", "4"),
        CompletionStatusV2.COMPLETE,
    )
    left = _unit("source-unit", 0x1000, "5")
    right = _unit("library-unit", 0x1010, "6")
    ledger = ImplementationLedgerV2.create(
        profile=profile,
        binary=_binary(),
        structural_units=[left, right],
        ownership_records=[
            UnitOwnershipRecordV2.create(
                owner=_owner(
                    ImplementationOwnerKindV2.PORTABLE_COMPONENT,
                    "portable-source",
                    source.identity,
                    "7",
                ),
                units=[left],
            ),
            UnitOwnershipRecordV2.create(
                owner=_owner(
                    ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION,
                    "library-substitution",
                    library.identity,
                    "8",
                ),
                units=[right],
            ),
        ],
    )
    return ledger, source, library


def _candidates(
    runtime: CompletionEvidenceV2,
) -> tuple[CandidateIdentityV2, CandidateIdentityV2]:
    common = {
        "source_project_sha256": _digest("9"),
        "runtime_lock_sha256": runtime.identity.sha256,
    }
    pe32 = CandidateIdentityV2(
        identity=_artifact("candidate-build", "candidate-pe32", "0"),
        platform=CandidatePlatformV2.PE32,
        architecture="i686",
        target_triple="i686-w64-mingw32",
        binary_sha256=_digest("1"),
        build_manifest_sha256=_digest("2"),
        **common,
    )
    non_x86 = CandidateIdentityV2(
        identity=_artifact("candidate-build", "candidate-aarch64", "3"),
        platform=CandidatePlatformV2.NON_X86,
        architecture="aarch64",
        target_triple="aarch64-unknown-linux-gnu",
        binary_sha256=_digest("4"),
        build_manifest_sha256=_digest("5"),
        **common,
    )
    return pe32, non_x86


def _portable_receipt(
    profile: CompletionProfileV2 = CompletionProfileV2.PORTABLE_APPLICATION,
    *,
    validation: bool = False,
) -> LiftCompletionReceiptV2:
    fallback = _fallback()
    runtime = _runtime()
    ledger, source, library = _portable_materials(profile)
    pe32, non_x86 = _candidates(runtime)
    validation_evidence = (
        ValidationEvidenceV2(
            identity=_artifact("candidate-validation-v1", "validation", "6"),
            status=CompletionStatusV2.COMPLETE,
            pe32_candidate_sha256=pe32.binary_sha256,
            non_x86_candidate_sha256=non_x86.binary_sha256,
        )
        if validation
        else None
    )
    return LiftCompletionReceiptV2.create(
        profile=profile,
        final_authority=_final(),
        fallback_coverage=fallback,
        implementation_ledger=ledger.to_binding(),
        source_qualifications=[source],
        library_qualifications=[library],
        runtime_lock=runtime,
        pe32_candidate=pe32,
        non_x86_candidate=non_x86,
        validation=validation_evidence,
    )


def _codes(receipt: LiftCompletionReceiptV2) -> set[str]:
    return {issue.code for issue in receipt.issues}


class LiftCompletionReceiptV2Tests(unittest.TestCase):
    def test_static_baseline_completes_without_candidates(self) -> None:
        fallback = _fallback()
        ledger = _static_ledger(fallback)
        receipt = LiftCompletionReceiptV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            final_authority=_final(),
            fallback_coverage=fallback,
            implementation_ledger=ledger.to_binding(),
            runtime_lock=_runtime(),
        )

        self.assertIs(receipt.status, CompletionStatusV2.COMPLETE)
        self.assertTrue(receipt.authorizing)
        self.assertEqual(receipt.issues, ())

    def test_portable_application_binds_both_candidates_and_qualifications(self) -> None:
        receipt = _portable_receipt()

        self.assertIs(receipt.status, CompletionStatusV2.COMPLETE)
        self.assertTrue(receipt.authorizing)
        self.assertEqual(
            LiftCompletionReceiptV2.parse(json.loads(receipt.to_json())),
            receipt,
        )
        self.assertEqual(receipt.artifact_identity.artifact_id, receipt.receipt_id)

    def test_create_canonicalizes_qualification_order(self) -> None:
        receipt = _portable_receipt()
        source = receipt.source_qualifications[0]
        extra = CompletionEvidenceV2(
            _artifact("source-qualification-v1", "aaa-extra", "a"),
            CompletionStatusV2.COMPLETE,
        )
        one = LiftCompletionReceiptV2.create(
            profile=receipt.profile,
            final_authority=receipt.final_authority,
            fallback_coverage=receipt.fallback_coverage,
            implementation_ledger=receipt.implementation_ledger,
            source_qualifications=[source, extra],
            library_qualifications=receipt.library_qualifications,
            runtime_lock=receipt.runtime_lock,
            pe32_candidate=receipt.pe32_candidate,
            non_x86_candidate=receipt.non_x86_candidate,
        )
        two = LiftCompletionReceiptV2.create(
            profile=receipt.profile,
            final_authority=receipt.final_authority,
            fallback_coverage=receipt.fallback_coverage,
            implementation_ledger=receipt.implementation_ledger,
            source_qualifications=[extra, source],
            library_qualifications=receipt.library_qualifications,
            runtime_lock=receipt.runtime_lock,
            pe32_candidate=receipt.pe32_candidate,
            non_x86_candidate=receipt.non_x86_candidate,
        )

        self.assertEqual(one.to_payload(), two.to_payload())
        self.assertEqual(one.receipt_id, two.receipt_id)

    def test_validation_qualified_requires_and_accepts_matching_validation(self) -> None:
        receipt = _portable_receipt(
            CompletionProfileV2.VALIDATION_QUALIFIED,
            validation=True,
        )

        self.assertIs(receipt.status, CompletionStatusV2.COMPLETE)
        self.assertTrue(receipt.authorizing)

    def test_missing_required_evidence_is_incomplete(self) -> None:
        receipt = LiftCompletionReceiptV2.create(
            profile=CompletionProfileV2.STATIC_BASELINE,
            final_authority=None,
            fallback_coverage=None,
            implementation_ledger=None,
            runtime_lock=None,
        )

        self.assertIs(receipt.status, CompletionStatusV2.INCOMPLETE)
        self.assertFalse(receipt.authorizing)
        self.assertEqual(_codes(receipt), {"required_evidence_missing"})

    def test_portable_profile_requires_a_candidate_pair(self) -> None:
        complete = _portable_receipt()
        receipt = dataclasses.replace(complete, non_x86_candidate=None)

        self.assertIs(receipt.status, CompletionStatusV2.INCOMPLETE)
        self.assertTrue(
            {"candidate_identity_missing", "candidate_pair_incomplete"}
            <= _codes(receipt)
        )

    def test_validation_profile_without_validation_is_incomplete(self) -> None:
        receipt = _portable_receipt(
            CompletionProfileV2.VALIDATION_QUALIFIED,
            validation=False,
        )

        self.assertIs(receipt.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("validation_evidence_missing", _codes(receipt))

    def test_missing_source_or_library_qualification_is_incomplete(self) -> None:
        receipt = _portable_receipt()
        no_source = dataclasses.replace(receipt, source_qualifications=())
        no_library = dataclasses.replace(receipt, library_qualifications=())

        self.assertIs(no_source.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("source_qualification_missing", _codes(no_source))
        self.assertIs(no_library.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("library_qualification_missing", _codes(no_library))

    def test_violated_or_incomplete_bound_evidence_propagates(self) -> None:
        receipt = _portable_receipt()
        incomplete_runtime = dataclasses.replace(
            receipt,
            runtime_lock=_runtime(CompletionStatusV2.INCOMPLETE),
        )
        violated_library = dataclasses.replace(
            receipt,
            library_qualifications=(
                dataclasses.replace(
                    receipt.library_qualifications[0],
                    status=CompletionStatusV2.VIOLATED,
                ),
            ),
        )

        self.assertIs(incomplete_runtime.status, CompletionStatusV2.INCOMPLETE)
        self.assertIn("bound_evidence_incomplete", _codes(incomplete_runtime))
        self.assertIs(violated_library.status, CompletionStatusV2.VIOLATED)
        self.assertIn("bound_evidence_violated", _codes(violated_library))

    def test_final_authority_decision_and_pe_mismatches_are_violated(self) -> None:
        receipt = _portable_receipt()
        not_authorizing = dataclasses.replace(
            receipt,
            final_authority=_final(authorizing=False),
        )
        wrong_pe = dataclasses.replace(
            receipt,
            final_authority=_final(pe_sha256=_digest("f")),
        )

        self.assertIs(not_authorizing.status, CompletionStatusV2.VIOLATED)
        self.assertIn(
            "final_authority_decision_inconsistent", _codes(not_authorizing)
        )
        self.assertIs(wrong_pe.status, CompletionStatusV2.VIOLATED)
        self.assertIn("original_pe_binding_mismatch", _codes(wrong_pe))

    def test_ledger_profile_mismatch_is_violated(self) -> None:
        receipt = _portable_receipt()
        mismatched = dataclasses.replace(
            receipt,
            profile=CompletionProfileV2.VALIDATION_QUALIFIED,
        )

        self.assertIs(mismatched.status, CompletionStatusV2.VIOLATED)
        self.assertIn("ledger_profile_mismatch", _codes(mismatched))

    def test_duplicate_and_cross_classified_qualifications_are_violated(self) -> None:
        receipt = _portable_receipt()
        source = receipt.source_qualifications[0]
        duplicate = dataclasses.replace(
            receipt,
            source_qualifications=(source, source),
        )
        ambiguous = dataclasses.replace(
            receipt,
            library_qualifications=(source, *receipt.library_qualifications),
        )

        self.assertIs(duplicate.status, CompletionStatusV2.VIOLATED)
        self.assertIn("duplicate_qualification_evidence", _codes(duplicate))
        self.assertIs(ambiguous.status, CompletionStatusV2.VIOLATED)
        self.assertIn("ambiguous_qualification_evidence", _codes(ambiguous))

    def test_candidate_source_and_runtime_mismatches_are_violated(self) -> None:
        receipt = _portable_receipt()
        assert receipt.non_x86_candidate is not None
        source_mismatch = dataclasses.replace(
            receipt,
            non_x86_candidate=dataclasses.replace(
                receipt.non_x86_candidate,
                source_project_sha256=_digest("f"),
            ),
        )
        runtime_mismatch = dataclasses.replace(
            receipt,
            non_x86_candidate=dataclasses.replace(
                receipt.non_x86_candidate,
                runtime_lock_sha256=_digest("f"),
            ),
        )

        self.assertIs(source_mismatch.status, CompletionStatusV2.VIOLATED)
        self.assertIn("candidate_source_project_mismatch", _codes(source_mismatch))
        self.assertIs(runtime_mismatch.status, CompletionStatusV2.VIOLATED)
        self.assertIn("candidate_runtime_lock_mismatch", _codes(runtime_mismatch))

    def test_validation_must_bind_exact_candidate_binaries(self) -> None:
        receipt = _portable_receipt(
            CompletionProfileV2.VALIDATION_QUALIFIED,
            validation=True,
        )
        assert receipt.validation is not None
        mismatch = dataclasses.replace(
            receipt,
            validation=dataclasses.replace(
                receipt.validation,
                pe32_candidate_sha256=_digest("f"),
            ),
        )

        self.assertIs(mismatch.status, CompletionStatusV2.VIOLATED)
        self.assertIn("validation_candidate_binding_mismatch", _codes(mismatch))

    def test_parser_rejects_stale_status_authorizing_issues_and_id(self) -> None:
        receipt = _portable_receipt()
        for mutation in ("status", "authorizing", "issues", "receipt_id"):
            with self.subTest(mutation=mutation):
                payload = json.loads(receipt.to_json())
                if mutation == "status":
                    payload["status"] = "incomplete"
                elif mutation == "authorizing":
                    payload["authorizing"] = False
                elif mutation == "issues":
                    payload["issues"] = [{
                        "status": "incomplete",
                        "code": "forged",
                        "location": "receipt",
                        "detail": "forged issue",
                    }]
                else:
                    payload["receipt_id"] = (
                        "lift-completion-receipt-v2:" + _digest("0")
                    )
                with self.assertRaises(AuthorityDataError):
                    LiftCompletionReceiptV2.parse(payload)

    def test_candidate_types_and_receipt_are_immutable(self) -> None:
        runtime = _runtime()
        with self.assertRaises(AuthorityDataError):
            CandidateIdentityV2(
                identity=_artifact("candidate-build", "not-portable", "1"),
                platform=CandidatePlatformV2.NON_X86,
                architecture="x86_64",
                target_triple="x86_64-unknown-linux-gnu",
                binary_sha256=_digest("2"),
                build_manifest_sha256=_digest("3"),
                source_project_sha256=_digest("4"),
                runtime_lock_sha256=runtime.identity.sha256,
            )

        receipt = _portable_receipt()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.profile = CompletionProfileV2.STATIC_BASELINE  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
