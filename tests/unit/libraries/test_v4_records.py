from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from spaghetti_extractor.libraries.v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    LIBRARY_ADOPTION_INTENT_CODEC_V1,
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    CheckedLibraryIslandV1,
    LibraryAdoptionIntentV1,
    LibraryOperationSourceMappingV1,
    ReusableLibraryImplementationV1,
)
from spaghetti_extractor.libraries.v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryIslandIssueV4,
    LibraryReleaseHypothesesV4,
    LibraryReleaseIssueV4,
)
from spaghetti_extractor.libraries.v4_record_support import (
    LibraryV4RecordError,
)


def digest(character: str) -> str:
    return character * 64


class V4RecordFixtures:
    @staticmethod
    def match(
        *,
        target_function_id: str = "target.fn.print",
        target_span_start: int = 0x401000,
        target_span_end: int = 0x401020,
        target_unit_ids: tuple[str, ...] = ("unit.1", "unit.2"),
        catalog_function_id: str = "catalog.fn.print",
        score: int = 940,
    ) -> LibraryFunctionMatchV4:
        return LibraryFunctionMatchV4.create(
            target_function_id=target_function_id,
            target_span_start=target_span_start,
            target_span_end=target_span_end,
            target_unit_ids=target_unit_ids,
            catalog_function_id=catalog_function_id,
            evidence=("exact_bytes", "direct_calls", "abi_envelope"),
            score=score,
        )

    @classmethod
    def island(
        cls,
        *,
        target_id: str = "hello.exe",
        family_id: str = "ucrt",
        release_id: str = "ucrt-10.0.22621",
        match: LibraryFunctionMatchV4 | None = None,
        issues: tuple[LibraryIslandIssueV4, ...] = (),
        implementation_ids: tuple[str, ...] = ("implementation.printf",),
    ) -> LibraryIslandHypothesisV4:
        selected_match = match or cls.match()
        return LibraryIslandHypothesisV4.create(
            target_id=target_id,
            family_id=family_id,
            release_id=release_id,
            target_unit_ids=selected_match.target_unit_ids,
            member_ids=("archive-member:stdio.obj",),
            catalog_function_ids=(selected_match.catalog_function_id,),
            operation_ids=("operation.printf",),
            matches=(selected_match,),
            boundary_edge_ids=("edge.stderr", "edge.stdout"),
            implementation_ids=implementation_ids,
            issues=issues,
        )

    @classmethod
    def release(
        cls,
        *,
        islands: tuple[LibraryIslandHypothesisV4, ...] | None = None,
        issues: tuple[LibraryReleaseIssueV4, ...] = (),
    ) -> LibraryReleaseHypothesesV4:
        return LibraryReleaseHypothesesV4.create(
            target_id="hello.exe",
            family_id="ucrt",
            release_id="ucrt-10.0.22621",
            target_binary_sha256=digest("a"),
            target_signature_graph_sha256=digest("b"),
            catalog_search_index_sha256=digest("c"),
            catalog_release_sha256=digest("d"),
            islands=islands or (cls.island(),),
            issues=issues,
        )


class LibraryReleaseHypothesesV4Tests(unittest.TestCase):
    def test_round_trip_preserves_match_and_independent_statuses(self) -> None:
        boundary_issue = LibraryIslandIssueV4.create(
            family="boundary",
            status="incomplete",
            code="callback_abi_missing",
            message="callback ABI has not been recovered",
            location="boundaries.edge.callback",
        )
        implementation_issue = LibraryIslandIssueV4.create(
            family="implementation",
            status="violated",
            code="source_hash_mismatch",
            message="selected source does not match the checked recipe",
            location="implementations.implementation.printf",
        )
        ambiguity = LibraryReleaseIssueV4.create(
            status="incomplete",
            code="release_ambiguous",
            message="two ABI-compatible releases remain",
            location="release",
            competing_release_ids=("ucrt-10.0.19041", "ucrt-10.0.22621"),
        )
        island = V4RecordFixtures.island(
            issues=(implementation_issue, boundary_issue)
        )
        artifact = V4RecordFixtures.release(islands=(island,), issues=(ambiguity,))

        decoded = LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.dumps(artifact)
        )

        self.assertEqual(decoded, artifact)
        self.assertEqual(decoded.status, "violated")
        self.assertEqual(decoded.islands[0].identity_status, "complete")
        self.assertEqual(decoded.islands[0].boundary_status, "incomplete")
        self.assertEqual(decoded.islands[0].implementation_status, "violated")
        self.assertEqual(decoded.islands[0].matches[0].target_span_start, 0x401000)
        self.assertEqual(decoded.issues[0].competing_release_ids[0], "ucrt-10.0.19041")

    def test_codec_file_round_trip(self) -> None:
        artifact = V4RecordFixtures.release()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-hypotheses.json"
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(path, artifact)
            self.assertEqual(
                LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.read(path), artifact
            )

    def test_unknown_and_missing_fields_are_rejected(self) -> None:
        payload = V4RecordFixtures.release().to_payload()
        payload["unexpected"] = True
        with self.assertRaisesRegex(LibraryV4RecordError, "unknown fields"):
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(json.dumps(payload))

        payload = V4RecordFixtures.release().to_payload()
        del payload["target_binary_sha256"]
        with self.assertRaisesRegex(LibraryV4RecordError, "missing fields"):
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(json.dumps(payload))

    def test_upstream_hash_corruption_is_rejected(self) -> None:
        payload = V4RecordFixtures.release().to_payload()
        payload["target_signature_graph_sha256"] = digest("e")
        with self.assertRaisesRegex(LibraryV4RecordError, "does not bind"):
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(json.dumps(payload))

    def test_island_cannot_cross_release_scope(self) -> None:
        wrong_release = V4RecordFixtures.island(release_id="ucrt-10.0.19041")
        with self.assertRaisesRegex(LibraryV4RecordError, "different target"):
            V4RecordFixtures.release(islands=(wrong_release,))

    def test_noncanonical_nested_order_is_rejected(self) -> None:
        payload = V4RecordFixtures.release().to_payload()
        payload["islands"][0]["target_unit_ids"] = ["unit.2", "unit.1"]
        with self.assertRaisesRegex(LibraryV4RecordError, "canonically sorted"):
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(json.dumps(payload))

    def test_status_without_local_issue_is_rejected(self) -> None:
        payload = V4RecordFixtures.release().to_payload()
        payload["islands"][0]["identity_status"] = "incomplete"
        with self.assertRaisesRegex(LibraryV4RecordError, "from local issues"):
            LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.loads(json.dumps(payload))

    def test_function_match_scope_and_identity_are_checked(self) -> None:
        match = V4RecordFixtures.match(
            target_unit_ids=("unit.2", "unit.1"), score=975
        )
        self.assertEqual(match.target_unit_ids, ("unit.1", "unit.2"))
        self.assertEqual(
            match.evidence, ("abi_envelope", "direct_calls", "exact_bytes")
        )

        payload = match.to_payload()
        payload["score"] = 976
        with self.assertRaisesRegex(LibraryV4RecordError, "does not bind"):
            LibraryFunctionMatchV4.from_payload(payload, "match")

        outside_match = V4RecordFixtures.match(target_unit_ids=("unit.3",))
        with self.assertRaisesRegex(LibraryV4RecordError, "outside the island"):
            LibraryIslandHypothesisV4.create(
                target_id="hello.exe",
                family_id="ucrt",
                release_id="ucrt-10.0.22621",
                target_unit_ids=("unit.1",),
                member_ids=("archive-member:stdio.obj",),
                catalog_function_ids=(outside_match.catalog_function_id,),
                operation_ids=("operation.printf",),
                matches=(outside_match,),
            )

    def test_records_are_immutable(self) -> None:
        island = V4RecordFixtures.island()
        with self.assertRaises(FrozenInstanceError):
            island.release_id = "changed"  # type: ignore[misc]


class CheckedLibraryIslandV1Tests(unittest.TestCase):
    def test_round_trip_and_corruption(self) -> None:
        issue = LibraryIslandIssueV4.create(
            family="boundary",
            status="incomplete",
            code="resource_edge_missing",
            message="resource edge remains unresolved",
            location="boundaries.resource.1",
        )
        receipt = CheckedLibraryIslandV1.create(
            target_id="hello.exe",
            target_binary_sha256=digest("b"),
            machine_ir_sha256=digest("c"),
            island_id=V4RecordFixtures.island().island_id,
            hypotheses_sha256=digest("e"),
            implementation_id="implementation.printf",
            implementation_sha256=digest("d"),
            checker_id="library-island-checker-v1",
            checked_unit_ids=("unit.2", "unit.1"),
            checked_operation_ids=("operation.printf",),
            checked_boundary_edge_ids=("edge.stdout",),
            dependency_sha256s=(digest("f"), digest("a")),
            issues=(issue,),
        )
        self.assertEqual(receipt.status, "incomplete")
        self.assertEqual(receipt.checked_unit_ids, ("unit.1", "unit.2"))
        self.assertEqual(
            CHECKED_LIBRARY_ISLAND_CODEC_V1.loads(
                CHECKED_LIBRARY_ISLAND_CODEC_V1.dumps(receipt)
            ),
            receipt,
        )

        payload = receipt.to_payload()
        payload["receipt_sha256"] = digest("0")
        with self.assertRaisesRegex(LibraryV4RecordError, "does not bind"):
            CHECKED_LIBRARY_ISLAND_CODEC_V1.loads(json.dumps(payload))


class ReusableLibraryImplementationV1Tests(unittest.TestCase):
    @staticmethod
    def mapping(operation: str, source: str, character: str):
        return LibraryOperationSourceMappingV1.create(
            operation_id=operation,
            source_id=source,
            source_symbol=f"portable_{operation.split('.')[-1]}",
            source_sha256=digest(character),
        )

    def test_multiple_operation_source_mappings_round_trip(self) -> None:
        implementation = ReusableLibraryImplementationV1.create(
            family_id="ucrt",
            recipe_id="recipe.stdio.portable-v1",
            compatible_release_ids=("ucrt-b", "ucrt-a", "ucrt-a"),
            operation_source_mappings=(
                self.mapping("operation.puts", "source.stdio", "2"),
                self.mapping("operation.printf", "source.stdio", "1"),
            ),
            interface_contract_ids=("interface.stdio-v1",),
            effect_contract_ids=("effects.stdio-v1",),
            compile_profile_id="compile.mingw32-c11-v1",
            qualification_checker_id="component-refinement-checker-v1",
            qualification_receipt_sha256=digest("3"),
        )
        decoded = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.loads(
            REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.dumps(implementation)
        )
        self.assertEqual(decoded, implementation)
        self.assertEqual(implementation.compatible_release_ids, ("ucrt-a", "ucrt-b"))
        self.assertEqual(len(implementation.operation_source_mappings), 2)

    def test_duplicate_operation_mapping_is_rejected(self) -> None:
        first = self.mapping("operation.printf", "source.one", "1")
        second = self.mapping("operation.printf", "source.two", "2")
        with self.assertRaisesRegex(LibraryV4RecordError, "exactly one source"):
            ReusableLibraryImplementationV1.create(
                family_id="ucrt",
                recipe_id="recipe.invalid",
                compatible_release_ids=("ucrt-a",),
                operation_source_mappings=(first, second),
            )

    def test_source_hash_alone_cannot_be_complete(self) -> None:
        mapping = self.mapping("operation.printf", "source.stdio", "1")
        with self.assertRaisesRegex(
            LibraryV4RecordError, "complete implementation requires"
        ):
            ReusableLibraryImplementationV1.create(
                family_id="ucrt",
                recipe_id="recipe.unqualified",
                compatible_release_ids=("ucrt-a",),
                operation_source_mappings=(mapping,),
            )

        issue = LibraryIslandIssueV4.create(
            family="implementation",
            status="incomplete",
            code="qualification_missing",
            message="compile and refinement evidence has not been checked",
            location="qualification",
        )
        proposal = ReusableLibraryImplementationV1.create(
            family_id="ucrt",
            recipe_id="recipe.unqualified",
            compatible_release_ids=("ucrt-a",),
            operation_source_mappings=(mapping,),
            issues=(issue,),
        )
        self.assertEqual(proposal.status, "incomplete")

    def test_mapping_corruption_is_rejected(self) -> None:
        payload = self.mapping("operation.printf", "source.stdio", "1").to_payload()
        payload["source_symbol"] = "forged_symbol"
        with self.assertRaisesRegex(LibraryV4RecordError, "does not bind"):
            LibraryOperationSourceMappingV1.from_payload(payload, "mapping")


class LibraryAdoptionIntentV1Tests(unittest.TestCase):
    def test_adopt_and_draft_round_trip(self) -> None:
        adopt = LibraryAdoptionIntentV1.create(
            target_id="hello.exe",
            island_id=V4RecordFixtures.island().island_id,
            hypotheses_sha256=digest("a"),
            implementation_id="implementation.printf",
            mode="adopt",
        )
        draft = LibraryAdoptionIntentV1.create(
            target_id="hello.exe",
            island_id=V4RecordFixtures.island().island_id,
            hypotheses_sha256=digest("a"),
            recipe_id="recipe.printf.draft",
            mode="draft",
        )
        for intent in (adopt, draft):
            self.assertEqual(
                LIBRARY_ADOPTION_INTENT_CODEC_V1.loads(
                    LIBRARY_ADOPTION_INTENT_CODEC_V1.dumps(intent)
                ),
                intent,
            )

    def test_selection_and_mode_are_strict(self) -> None:
        with self.assertRaisesRegex(LibraryV4RecordError, "exactly one"):
            LibraryAdoptionIntentV1.create(
                target_id="hello.exe",
                island_id="island",
                hypotheses_sha256=digest("a"),
                implementation_id="implementation",
                recipe_id="recipe",
                mode="draft",
            )
        with self.assertRaisesRegex(LibraryV4RecordError, "requires"):
            LibraryAdoptionIntentV1.create(
                target_id="hello.exe",
                island_id="island",
                hypotheses_sha256=digest("a"),
                recipe_id="recipe",
                mode="adopt",
            )

    def test_intent_corruption_is_rejected(self) -> None:
        intent = LibraryAdoptionIntentV1.create(
            target_id="hello.exe",
            island_id="island",
            hypotheses_sha256=digest("a"),
            implementation_id="implementation",
            mode="adopt",
        )
        payload = intent.to_payload()
        payload["target_id"] = "other.exe"
        with self.assertRaisesRegex(LibraryV4RecordError, "does not bind"):
            LIBRARY_ADOPTION_INTENT_CODEC_V1.loads(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
