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
        "paths": {"nix": "default.nix", "components": "intent/components.json"},
        "workflow": {"default_configuration": "default"},
    }


class TargetMetadataTests(unittest.TestCase):
    def test_strict_metadata_parses(self) -> None:
        value = TargetMetadata.parse(_metadata())
        self.assertEqual(value.identity, "fixture")
        self.assertEqual(value.input.expected_sha256, "1" * 64)
        self.assertEqual(value.workflow.default_configuration, "default")

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
        payload["workflow"]["default_configuration"] = None
        value = TargetMetadata.parse(payload)
        self.assertIsNone(value.workflow.default_configuration)
        self.assertEqual(dict(value.paths), {"nix": Path("default.nix")})

    def test_component_path_and_configuration_are_atomic(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        with self.assertRaisesRegex(TargetMetadataError, "both be set or both be null"):
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
        self.assertFalse(result["authority"])
        self.assertEqual(
            result["counts"]["blockers"], len(module["semantic_holes"])
        )
        subject = result["subjects"][0]
        self.assertEqual(subject["subject"], "module:fixture")
        self.assertEqual(subject["blockers"], module["semantic_holes"])
        self.assertFalse(subject["authority"])
        self.assertNotIn("configuration_id", result)
        self.assertNotIn("component_configuration", result)
        self.assertNotIn("candidate", result)

    def test_semantic_module_reports_non_authorizing_subject_state(self) -> None:
        module = self._module(blockers=[])
        result = self._build(module)
        self.assertEqual(result["status"], module["status"])
        self.assertFalse(result["authority"])
        self.assertFalse(result["subjects"][0]["authority"])
        self.assertEqual(
            result["subjects"][0]["ranked_next_action"],
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


class CandidateStatusTests(unittest.TestCase):
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
        module_blockers: list[dict[str, object]] | None = None,
        blockers: list[dict[str, object]] | None = None,
        selection_module_sha256: str | None = None,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_path = root / "linked-semantic-module.json"
            selection_path = root / "implementation-selection.json"
            output = root / "status.json"
            module = ProjectStatusTests._module(
                blockers=module_blockers or []
            )
            module_path.write_text(json.dumps(module), encoding="ascii")
            selection_path.write_text(
                json.dumps(self._selection(
                    module_sha256=(
                        selection_module_sha256
                        or str(module["linked_semantic_module_sha256"])
                    ),
                    blockers=blockers,
                )),
                encoding="ascii",
            )
            return build_project_status(
                target_id="fixture",
                linked_semantic_module=module_path,
                implementation_selection=selection_path,
                configuration_id="default",
                out=output,
            )

    def test_ready_selection_is_a_compact_configuration_subject(self) -> None:
        result = self._build()
        self.assertEqual(result["format"], OPERATOR_WORK_STATUS_FORMAT)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["counts"]["subjects"], 2)
        configuration = next(
            row for row in result["subjects"]
            if row["subject"] == "configuration:fixture:default"
        )
        self.assertFalse(configuration["authority"])
        self.assertEqual(configuration["state"], "complete")
        self.assertTrue(configuration["bindings"][0]["ready_for_realization"])
        self.assertEqual(configuration["bindings"][0]["selected_symbols"], 1)

    def test_selection_blockers_remain_distinct_from_module_blockers(self) -> None:
        result = self._build(
            module_blockers=[{"code": "reachable_symbol_unresolved"}],
            blockers=[{"code": "source_missing", "detail": "write source"}],
        )
        subjects = {row["subject"]: row for row in result["subjects"]}
        self.assertNotEqual(subjects["module:fixture"]["blockers"], [])
        self.assertEqual(
            subjects["configuration:fixture:default"]["blockers"],
            [{"code": "source_missing", "detail": "write source"}],
        )

    def test_selection_for_another_module_is_rejected(self) -> None:
        with self.assertRaisesRegex(StatusArtifactError, "another linked semantic"):
            self._build(selection_module_sha256="f" * 64)

    def test_status_hash_is_deterministic(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(first["view_sha256"], second["view_sha256"])


if __name__ == "__main__":
    unittest.main()
