from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    LINKED_ISLAND_INTENT_FORMAT,
    SOURCE_PROJECT_INTENT_FORMAT,
    TARGET_BUNDLE_FORMAT,
)
from spaghetti_extractor.target_intent import (
    TargetIntentError,
    load_target_bundle,
    resolve_linked_island_intent,
    resolve_source_project_intent,
    validate_authored_intent,
)
from spaghetti_extractor.util import write_json

class TargetIntentTests(unittest.TestCase):
    def test_target_bundle_contains_only_pins_and_relative_authored_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "intent").mkdir()
            (root / "intent/components.json").write_text("{}\n", encoding="ascii")
            write_json(
                root / "target.json",
                {
                    "format": TARGET_BUNDLE_FORMAT,
                    "id": "sample-pe",
                    "display_name": "Sample PE",
                    "input": {"kind": "pe32", "expected_sha256": "a" * 64},
                    "paths": {"components": "intent/components.json"},
                },
            )

            bundle = load_target_bundle(root)

            self.assertEqual(bundle.identity.target_id, "sample-pe")
            self.assertEqual(bundle.identity.expected_sha256, "a" * 64)

    def test_target_bundle_rejects_escaping_or_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "target.json",
                {
                    "format": TARGET_BUNDLE_FORMAT,
                    "id": "sample-pe",
                    "display_name": "Sample PE",
                    "input": {"kind": "pe32", "expected_sha256": "a" * 64},
                    "paths": {"components": "../outside.json"},
                },
            )
            with self.assertRaisesRegex(TargetIntentError, "normalized relative"):
                load_target_bundle(root)

    def test_target_bundle_rejects_unknown_path_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "legacy.json").write_text("{}\n", encoding="ascii")
            write_json(
                root / "target.json",
                {
                    "format": TARGET_BUNDLE_FORMAT,
                    "id": "sample-pe",
                    "display_name": "Sample PE",
                    "input": {"kind": "pe32", "expected_sha256": "a" * 64},
                    "paths": {"slice_profile": "legacy.json"},
                },
            )

            with self.assertRaisesRegex(
                TargetIntentError, "unsupported target path labels"
            ):
                load_target_bundle(root)

    def test_target_bundle_pairs_source_projects_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "project.json").write_text("{}\n", encoding="ascii")
            write_json(
                root / "target.json",
                {
                    "format": TARGET_BUNDLE_FORMAT,
                    "id": "sample-pe",
                    "display_name": "Sample PE",
                    "input": {"kind": "pe32", "expected_sha256": "a" * 64},
                    "paths": {"source_projects": ["project.json"]},
                },
            )

            with self.assertRaisesRegex(TargetIntentError, "equal lengths"):
                load_target_bundle(root)

    def test_authored_intent_rejects_generated_fields_recursively(self) -> None:
        with self.assertRaisesRegex(TargetIntentError, "proposal_binding_sha256"):
            validate_authored_intent(
                {
                    "format": "fixture-intent-v1",
                    "components": [
                        {"proposal_binding_sha256": "a" * 64}
                    ],
                },
                expected_format="fixture-intent-v1",
                context="fixture intent",
            )

    def test_linked_island_intent_derives_binary_binding_and_self_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "intent.json",
                {
                    "format": LINKED_ISLAND_INTENT_FORMAT,
                    "islands": [
                        {
                            "id": "application:sample",
                            "kind": "application",
                            "authority": "operator_reviewed_exact_range",
                            "provenance_hints": ["reviewed application range"],
                            "ranges": [{"rva_start": 0x1000, "rva_end": 0x1100}],
                        }
                    ],
                },
            )

            review = resolve_linked_island_intent(
                intent=root / "intent.json",
                original_sha256="c" * 64,
                out=root / "review.json",
            )

            self.assertEqual(review["original_binary_sha256"], "c" * 64)
            self.assertRegex(review["review_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("unclaimed_exact_units", review)

    def test_linked_island_intent_preserves_reviewed_exact_complement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = {
                "authority": "operator_reviewed_exact_complement",
                "id": "compiler-linker-support:runtime",
                "kind": "compiler_linker_support",
                "operator_reviewed": True,
                "replacement_authorized": False,
                "review_rationale": "Reviewed as pinned compiler runtime ownership.",
                "scope": "otherwise_unclaimed_exact_machine_units",
            }
            write_json(
                root / "intent.json",
                {
                    "format": LINKED_ISLAND_INTENT_FORMAT,
                    "islands": [],
                    "unclaimed_exact_units": policy,
                },
            )

            review = resolve_linked_island_intent(
                intent=root / "intent.json",
                original_sha256="e" * 64,
                out=root / "review.json",
            )

            self.assertEqual(review["unclaimed_exact_units"], policy)
            self.assertEqual(review["original_binary_sha256"], "e" * 64)

    def test_linked_island_complement_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "intent.json",
                {
                    "format": LINKED_ISLAND_INTENT_FORMAT,
                    "islands": [],
                    "unclaimed_exact_units": {
                        "authority": "operator_reviewed_exact_complement",
                        "id": "compiler-linker-support:runtime",
                        "kind": "compiler_linker_support",
                        "operator_reviewed": False,
                        "replacement_authorized": False,
                        "review_rationale": "Not actually reviewed.",
                        "scope": "otherwise_unclaimed_exact_machine_units",
                    },
                },
            )

            with self.assertRaisesRegex(TargetIntentError, "operator-reviewed"):
                resolve_linked_island_intent(
                    intent=root / "intent.json",
                    original_sha256="e" * 64,
                    out=root / "review.json",
                )

    def test_source_project_intent_derives_binary_binding_and_self_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(
                root / "intent.json",
                {
                    "format": SOURCE_PROJECT_INTENT_FORMAT,
                    "program_id": "sample-source-v1",
                    "sources": [{"path": "main.c"}],
                    "coverage_scope": {
                        "kind": "reviewed_machine_ranges",
                        "required_ranges": [
                            {"id": "main", "rva_start": 0x1000, "rva_end": 0x1020}
                        ],
                        "out_of_scope_policy": "linked_runtime_and_library_code",
                    },
                    "islands": [],
                },
            )

            project = resolve_source_project_intent(
                intent=root / "intent.json",
                original_sha256="d" * 64,
                out=root / "project.json",
            )

            self.assertEqual(project["original_binary_sha256"], "d" * 64)
            self.assertRegex(project["specification_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
