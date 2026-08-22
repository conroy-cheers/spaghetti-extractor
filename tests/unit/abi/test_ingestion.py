from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.abi.declarations import (
    PhysicalAbiDeclarationSetV1,
    PhysicalAbiDeclarationV1,
)
from spaghetti_extractor.abi.extraction import AbiExtractionResultV1
from spaghetti_extractor.abi.ingestion import (
    AbiDeclarationIngestionV1,
    CatalogMemberAbiDeclarationV1,
    CatalogMemberIdentityV1,
    ingest_abi_declarations,
)
from spaghetti_extractor.abi.model import AbiEvidenceV1, AbiFactV1, StackCleanupV1

from ._support import physical_profile


def _binding(
    *,
    declaration_profile=None,
    member_snapshot: str = "runtime-snapshot-v1",
    member_symbols: tuple[str, ...] = ("_run@4",),
) -> CatalogMemberAbiDeclarationV1:
    declaration = PhysicalAbiDeclarationV1.create(
        symbols=("_run@4",),
        source_kind="reviewed_definition",
        source_sha256="a" * 64,
        producer="fixture-review-ingestor-v1",
        profile=declaration_profile or physical_profile(),
        dependency_ids=("review:run-v1",),
    )
    declaration_set = PhysicalAbiDeclarationSetV1.create(
        snapshot_id="runtime-snapshot-v1",
        declarations=(declaration,),
    )
    member = CatalogMemberIdentityV1.create(
        catalog_id="fixture-runtime",
        snapshot_id=member_snapshot,
        source_index_sha256="b" * 64,
        function_id="library-function:run",
        member_id="member:runtime-object",
        symbols=member_symbols,
        exact_bytes_sha256="c" * 64,
        normalized_bytes_sha256="d" * 64,
    )
    return CatalogMemberAbiDeclarationV1.create(
        member=member,
        declaration_set=declaration_set,
        declaration_id=declaration.declaration_id,
    )


def _extraction(
    *, subject_id: str = "target-function:run", value: str = "cdecl"
) -> AbiExtractionResultV1:
    evidence = AbiEvidenceV1.create(
        kind="checked_call_boundary",
        producer="fixture-extractor-v1",
        subject_kind="library_member" if subject_id.startswith("library-") else "function",
        subject_id=subject_id,
        dependencies=("checked-summary-v1",),
        payload={"field": "calling_convention"},
    )
    fact = AbiFactV1.create(
        subject_id=subject_id,
        field="calling_convention",
        status="exact",
        values=(value,),
        evidence_ids=(evidence.evidence_id,),
        dependency_ids=("checked-summary-v1",),
    )
    return AbiExtractionResultV1(
        "complete",
        {
            subject_id: (
                "library_member" if subject_id.startswith("library-") else "function"
            )
        },
        (evidence,),
        (fact,),
        (),
        (),
    )


class AbiDeclarationIngestionTests(unittest.TestCase):
    def test_exact_member_carries_the_full_content_bound_declaration(self) -> None:
        binding = _binding()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ingestion.json"
            result = ingest_abi_declarations(
                member_declarations=(binding,), out=path
            )
            decoded = AbiDeclarationIngestionV1.read(path)

        self.assertEqual(result.status, "complete")
        self.assertEqual(decoded, result)
        self.assertEqual(
            result.member_declarations[0].member.source_index_sha256,
            "b" * 64,
        )
        self.assertEqual(
            result.member_declarations[0].declaration.source_sha256,
            "a" * 64,
        )
        self.assertEqual(len(result.facts), 9)
        self.assertEqual(len(result.evidence), 1)

    def test_existing_extraction_results_are_canonical_typed_records(self) -> None:
        extraction = _extraction()
        result = ingest_abi_declarations(extraction_results=(extraction,))

        self.assertEqual(result.status, "complete")
        self.assertEqual(result.subjects[0].subject_id, "target-function:run")
        self.assertEqual(result.evidence, extraction.evidence)
        self.assertEqual(result.facts, extraction.facts)

    def test_fact_conflicts_are_returned_as_contradictions(self) -> None:
        binding = _binding(
            declaration_profile=physical_profile(
                calling_convention="stdcall",
                stack_cleanup=StackCleanupV1("callee", 4),
            )
        )
        extraction = _extraction(subject_id="library-function:run", value="cdecl")

        result = ingest_abi_declarations(
            member_declarations=(binding,), extraction_results=(extraction,)
        )

        self.assertEqual(result.status, "contradiction")
        self.assertTrue(result.has_contradictions)
        self.assertIn(
            "abi_constraint_contradiction",
            {issue.code for issue in result.issues},
        )
        self.assertNotIn("violated", str(result.to_payload()))

    def test_snapshot_and_symbol_disagreement_fail_closed(self) -> None:
        result = ingest_abi_declarations(
            member_declarations=(
                _binding(
                    member_snapshot="runtime-snapshot-v2",
                    member_symbols=("_other@4",),
                ),
            )
        )

        self.assertEqual(result.status, "contradiction")
        self.assertEqual(
            {issue.code for issue in result.issues},
            {
                "abi_declaration_snapshot_contradiction",
                "abi_declaration_symbol_contradiction",
            },
        )

    def test_member_identity_is_content_bound(self) -> None:
        payload = _binding().member.to_payload()
        payload["member_id"] = "member:other-object"

        with self.assertRaisesRegex(ValueError, "does not bind its contents"):
            CatalogMemberIdentityV1.parse(payload)


if __name__ == "__main__":
    unittest.main()
