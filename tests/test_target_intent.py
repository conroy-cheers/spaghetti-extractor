from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_INTENT_FORMAT,
    COMPONENT_PROPOSAL_SET_FORMAT,
    COMPONENT_SELECTION_FORMAT,
    LINKED_ISLAND_INTENT_FORMAT,
    SOURCE_PROJECT_INTENT_FORMAT,
    TARGET_BUNDLE_FORMAT,
)
from spaghetti_extractor.target_intent import (
    TargetIntentError,
    load_target_bundle,
    resolve_component_intent,
    resolve_linked_island_intent,
    resolve_source_project_intent,
    validate_authored_intent,
)
from spaghetti_extractor.util import write_json


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


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

    def test_component_intent_resolves_unique_semantic_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposal_core = {
                "format": COMPONENT_PROPOSAL_SET_FORMAT,
                "status": "ready",
                "bindings": {},
                "proposals": [
                    {
                        "id": "generated:proposal:one",
                        "proposal_kinds": ["single_entry_control_closure"],
                        "membership": {
                            "rva_start": 0x1050,
                            "rva_end": 0x1070,
                            "unit_ids": ["generated:unit:one"],
                        },
                        "bindings": {"membership_bindings_sha256": "b" * 64},
                    }
                ],
            }
            proposals = {
                **proposal_core,
                "proposal_set_sha256": _digest(proposal_core),
            }
            write_json(root / "proposals.json", proposals)
            write_json(
                root / "intent.json",
                {
                    "format": COMPONENT_INTENT_FORMAT,
                    "program_id": "sample-pe-v1",
                    "components": [
                        {
                            "id": "startup",
                            "selector": {
                                "entry_rva": 0x1050,
                                "end_rva": 0x1070,
                                "proposal_kind": "single_entry_control_closure",
                            },
                            "label": "Startup",
                            "purpose": "Reviewed startup procedure",
                            "kind": "procedure",
                            "emission": {"policy": "function", "symbol": "startup"},
                        }
                    ],
                },
            )

            selection = resolve_component_intent(
                proposals=root / "proposals.json",
                intent=root / "intent.json",
                out=root / "selection.json",
            )

            self.assertEqual(selection["format"], COMPONENT_SELECTION_FORMAT)
            self.assertEqual(
                selection["components"][0]["proposal_id"],
                "generated:proposal:one",
            )
            self.assertEqual(
                selection["components"][0]["proposal_binding_sha256"],
                "b" * 64,
            )
            self.assertTrue((root / "component-selection.provenance.json").is_file())

    def test_component_intent_rejects_ambiguous_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposal_core = {
                "format": COMPONENT_PROPOSAL_SET_FORMAT,
                "proposals": [
                    {
                        "id": f"proposal:{index}",
                        "proposal_kinds": ["singleton"],
                        "membership": {"rva_start": 0x1050, "rva_end": 0x1060},
                    }
                    for index in range(2)
                ],
            }
            write_json(
                root / "proposals.json",
                {**proposal_core, "proposal_set_sha256": _digest(proposal_core)},
            )
            write_json(
                root / "intent.json",
                {
                    "format": COMPONENT_INTENT_FORMAT,
                    "program_id": "sample",
                    "components": [
                        {"id": "startup", "selector": {"entry_rva": 0x1050}}
                    ],
                },
            )
            with self.assertRaisesRegex(TargetIntentError, "resolved to 2 proposals"):
                resolve_component_intent(
                    proposals=root / "proposals.json",
                    intent=root / "intent.json",
                    out=root / "selection.json",
                )

    def test_authored_intent_rejects_generated_fields_recursively(self) -> None:
        with self.assertRaisesRegex(TargetIntentError, "proposal_binding_sha256"):
            validate_authored_intent(
                {
                    "format": COMPONENT_INTENT_FORMAT,
                    "components": [
                        {"proposal_binding_sha256": "a" * 64}
                    ],
                },
                expected_format=COMPONENT_INTENT_FORMAT,
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
