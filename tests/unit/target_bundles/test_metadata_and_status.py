from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.semantic_link.module_v2 import (
    build_linked_semantic_module_v2,
)
from spaghetti_extractor.semantic_link.may_link import (
    compile_semantic_may_link_facts_v2,
)
from spaghetti_extractor.target_bundles.metadata import (
    TargetMetadata,
    TargetMetadataError,
)
from spaghetti_extractor.operator.formats import OPERATOR_WORK_STATUS_FORMAT
from spaghetti_extractor.operator.projections import (
    _candidate_provider_coverage,
    project_candidate_selection,
)
from spaghetti_extractor.target_bundles.project_status import (
    StatusArtifactError,
    build_project_status,
)
from spaghetti_extractor.target_bundles.status_common import canonical_sha256
from tests.unit.semantic_link.fixture import SemanticLinkFixture


def _metadata() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-target-bundle-v3",
        "id": "fixture",
        "display_name": "Fixture PE32",
        "input": {"kind": "pe32", "expected_sha256": "1" * 64},
        "paths": {
            "nix": "default.nix",
            "components": "intent/components.json",
            "component_sources": "source",
        },
        "workflow": {"default_configuration": "default"},
    }


class TargetMetadataTests(unittest.TestCase):
    def test_strict_metadata_parses(self) -> None:
        value = TargetMetadata.parse(_metadata())
        self.assertEqual(value.identity, "fixture")
        self.assertEqual(value.input.expected_sha256, "1" * 64)
        self.assertEqual(value.workflow.default_configuration, "default")
        self.assertEqual(dict(value.paths)["component_sources"], Path("source"))

    def test_unknown_fields_bad_hashes_and_escaping_paths_fail(self) -> None:
        for mutate, pattern in (
            (lambda row: row.update({"extra": True}), "invalid fields"),
            (
                lambda row: row["input"].update({"expected_sha256": "bad"}),
                "not canonical",
            ),
            (
                lambda row: row["paths"].update({"nix": "../default.nix"}),
                "strict relative",
            ),
            (
                lambda row: row["paths"].pop("components"),
                "invalid fields",
            ),
        ):
            payload = _metadata()
            mutate(payload)
            with self.subTest(pattern=pattern), self.assertRaisesRegex(
                TargetMetadataError, pattern
            ):
                TargetMetadata.parse(payload)

    def test_analysis_only_metadata_has_no_fake_component_configuration(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        payload["paths"].pop("component_sources")
        payload["workflow"]["default_configuration"] = None
        value = TargetMetadata.parse(payload)
        self.assertIsNone(value.workflow.default_configuration)
        self.assertEqual(dict(value.paths), {"nix": Path("default.nix")})

    def test_component_path_and_configuration_are_atomic(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        payload["paths"].pop("component_sources")
        with self.assertRaisesRegex(TargetMetadataError, "both be set or both be null"):
            TargetMetadata.parse(payload)

    def test_component_source_path_requires_component_intent(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        payload["workflow"]["default_configuration"] = None
        with self.assertRaisesRegex(TargetMetadataError, "source path requires"):
            TargetMetadata.parse(payload)


class ProjectStatusTests(unittest.TestCase):
    @staticmethod
    def _module(*, blockers: list[dict[str, object]]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            SemanticLinkFixture().linked_facts(
                root, environment_blockers=tuple(blockers)
            )
            semantic, facts = compile_semantic_may_link_facts_v2(
                semantic_object=root / "semantic-object.json"
            )
            return build_linked_semantic_module_v2(
                semantic=semantic, link_facts=facts,
            )

    def _build(self, module: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_path = root / "linked-semantic-module.json"
            output = root / "status.json"
            module_path.write_text(json.dumps(module), encoding="ascii")
            return build_project_status(
                target_id="fixture",
                linked_semantic_module=module_path,
                out=output,
            )

    def test_incomplete_semantic_module_is_projected_without_candidate_state(self) -> None:
        blocker = {
            "code": "reachable_symbol_unresolved",
            "symbol_id": "external:function:kernel32.dll:exitprocess",
        }
        module = self._module(blockers=[blocker])
        result = self._build(module)
        self.assertEqual(result["format"], OPERATOR_WORK_STATUS_FORMAT)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["counts"]["blockers"], len(module["semantic_holes"])
        )
        subject = result["subjects"][0]
        self.assertEqual(subject["subject"], "module:fixture")
        self.assertEqual(subject["blockers"]["count"], len(module["semantic_holes"]))
        self.assertIn(
            module["semantic_holes"][0]["code"],
            {row["code"] for row in subject["blockers"]["groups"]},
        )
        self.assertEqual(subject["authority"], "not-applicable")
        self.assertNotIn("configuration_id", result)
        self.assertNotIn("component_configuration", result)
        self.assertNotIn("candidate", result)

    def test_semantic_module_reports_non_authorizing_subject_state(self) -> None:
        module = self._module(blockers=[])
        result = self._build(module)
        self.assertEqual(result["status"], module["status"])
        self.assertEqual(
            result["subjects"][0]["authority"], "not-applicable"
        )
        self.assertEqual(
            result["subjects"][0]["next_action"],
            f"resolve semantic hole {module['semantic_holes'][0]['code']}",
        )

    def test_stale_or_inconsistent_module_fails_closed(self) -> None:
        stale = self._module(blockers=[])
        stale["linked_semantic_module_sha256"] = "f" * 64
        with self.assertRaisesRegex(StatusArtifactError, "self hash is stale"):
            self._build(stale)
        inconsistent = self._module(blockers=[])
        inconsistent["status"] = "complete"
        core = dict(inconsistent)
        core.pop("linked_semantic_module_sha256")
        inconsistent["linked_semantic_module_sha256"] = canonical_sha256(core)
        with self.assertRaisesRegex(
            StatusArtifactError, "semantic-completeness status"
        ):
            self._build(inconsistent)


class CandidateProjectionTests(unittest.TestCase):
    def test_fallback_free_covers_definitions_and_obligations(self) -> None:
        coverage = _candidate_provider_coverage({
            "status": "complete",
            "definition_selections": [{
                "provider_kind": "qualified_portable_c",
            }],
            "obligation_selections": [{
                "provider_kind": "generated_behavioral_c",
            }],
        })
        self.assertFalse(coverage["fallback_free"])
        self.assertEqual(coverage["portable_progress"], "partial")

    @staticmethod
    def _selection(
        *,
        module_sha256: str,
        blockers: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        blocker_rows = blockers or []
        core: dict[str, object] = {
            "format": "spaghetti-extractor-implementation-selection-v2",
            "status": "complete" if not blocker_rows else "incomplete",
            "ready_for_realization": not blocker_rows,
            "mode": "hybrid",
            "bindings": {
                "linked_semantic_module_sha256": module_sha256,
            },
            "qualification_sha256s": ["4" * 64],
            "definition_selections": [{
                "definition_id": "semantic-definition-v2:" + "5" * 64,
                "symbol_id": "unit:entry",
                "provider_id": "generated",
                "provider_kind": "generated_behavioral_c",
                "qualification_sha256": "4" * 64,
                "native_symbol": "spx_entry",
            }],
            "obligation_selections": [],
            "blockers": blocker_rows,
        }
        return {**core, "selection_sha256": canonical_sha256(core)}

    def _build(
        self,
        *,
        blockers: list[dict[str, object]] | None = None,
    ) -> tuple[dict[str, object], list[dict[str, object]]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection_path = root / "implementation-selection.json"
            selection_path.write_text(
                json.dumps(self._selection(
                    module_sha256="3" * 64,
                    blockers=blockers,
                )),
                encoding="ascii",
            )
            return project_candidate_selection(
                target_id="fixture",
                configuration_id="default",
                path=selection_path,
            )

    def test_ready_selection_is_a_compact_configuration_subject(self) -> None:
        result, raw_blockers = self._build()
        self.assertEqual(result["format"], OPERATOR_WORK_STATUS_FORMAT)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["counts"]["subjects"], 1)
        configuration = result["subjects"][0]
        self.assertEqual(configuration["authority"], "not-applicable")
        self.assertEqual(configuration["state"], "complete")
        self.assertEqual(configuration["blockers"], {"count": 0, "groups": []})
        self.assertEqual(result["provider_coverage"], {
            "exact_selection": "complete",
            "portable_progress": "not-started",
            "fallback_free": False,
            "definitions": {
                "selected": 1,
                "by_kind": {
                    "external_environment": 0,
                    "generated_behavioral_c": 1,
                    "pinned_binary": 0,
                    "qualified_portable_c": 0,
                    "qualified_runtime": 0,
                },
                "portable_c": 0,
                "generated_behavioral_c": 1,
                "pinned_binary": 0,
                "portable_share_of_selected_basis_points": 0,
            },
            "obligations": {
                "selected": 0,
                "by_kind": {
                    "external_environment": 0,
                    "generated_behavioral_c": 0,
                    "pinned_binary": 0,
                    "qualified_portable_c": 0,
                    "qualified_runtime": 0,
                },
                "portable_c": 0,
                "generated_behavioral_c": 0,
                "pinned_binary": 0,
                "portable_share_of_selected_basis_points": None,
            },
        })
        self.assertEqual(raw_blockers, [])

    def test_selection_blockers_are_grouped_but_details_remain_available(self) -> None:
        result, raw_blockers = self._build(
            blockers=[{"code": "source_missing", "detail": "write source"}],
        )
        subject = result["subjects"][0]
        self.assertEqual(
            subject["blockers"]["groups"],
            [{
                "family": "provider-selection",
                "code": "source_missing",
                "count": 1,
                "example_location": "write source",
            }],
        )
        self.assertEqual(
            raw_blockers,
            [{"code": "source_missing", "detail": "write source"}],
        )

    def test_projection_is_deterministic(self) -> None:
        first, _ = self._build()
        second, _ = self._build()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
