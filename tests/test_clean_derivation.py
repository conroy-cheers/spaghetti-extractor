import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from haloce_catalog.clean_derivation import derive_clean_specs, promote_clean_templates, validate_clean_specs
from haloce_catalog.cli import main
from haloce_catalog.util import write_json


class CleanDerivationTests(unittest.TestCase):
    def test_unreviewed_templates_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "behavior-observations",
                "orbit",
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_orbit_seed7",
                    "review_status": "draft",
                    "taint_level": "clean_candidate",
                    "publication_decision": "not_reviewed",
                },
            )

            result = derive_clean_specs(corpus, root / "clean")
            spec = json.loads((root / "clean" / "specs.json").read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "pass")
        self.assertEqual(spec["summary"]["reviewed_records"], 0)
        self.assertEqual(spec["summary"]["skipped_templates"], 1)
        self.assertEqual(spec["test_records"], [])

    def test_reviewed_public_templates_emit_clean_specs_and_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "behavior-contracts",
                "gameplay",
                {
                    "entity_type": "behavior_contract",
                    "public_label": "contract_reference_gameplay",
                    "sanitized_name": "reference_gameplay_transcript",
                    "purpose_summary": "Defines deterministic frame transcript behavior.",
                    "inputs": {
                        "command_line": {"usage": "game.exe --json [--scenario NAME]"},
                        "scenario": "string",
                        "seed": "u32",
                        "frames": "u32",
                    },
                    "outputs": {"aggregate_hash": "u32"},
                },
            )
            self._write_template(
                corpus,
                "behavior-observations",
                "orbit",
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_orbit_seed7",
                    "sanitized_name": "orbit_seed7_180",
                    "purpose_summary": "Representative orbit scenario transcript.",
                    "inputs": {"scenario": "orbit", "seed": 7, "frames": 180},
                    "outputs": {"aggregate_hash": 2644509393},
                    "test_vectors": [{"input": {"seed": 7}, "output": {"aggregate_hash": 2644509393}}],
                },
            )
            self._write_template(
                corpus,
                "internal-routine-contracts",
                "routine-score",
                {
                    "entity_type": "internal_routine_contract",
                    "public_label": "routine_score_from_seed_v1",
                    "sanitized_name": "score_from_seed_v1",
                    "public_name": "score_from_seed_v1",
                    "purpose_summary": "Computes a deterministic score from a seed.",
                    "calling_convention": "cdecl",
                    "signature": "uint32 score_from_seed(uint32 seed)",
                    "input_shape": {"seed": "u32"},
                    "output_shape": {"score": "u32"},
                    "inputs": {"seed": "u32"},
                    "outputs": {"score": "u32"},
                    "evidence_source": "dynamic_observation",
                },
            )

            result = derive_clean_specs(corpus, root / "clean")
            spec = json.loads((root / "clean" / "specs.json").read_text(encoding="utf-8"))
            tests = json.loads((root / "clean" / "tests.json").read_text(encoding="utf-8"))
            payload = json.dumps(spec, sort_keys=True)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(spec["summary"]["reviewed_records"], 3)
        self.assertEqual(spec["summary"]["spec_records"], 2)
        self.assertEqual(spec["summary"]["test_records"], 1)
        self.assertEqual(tests["summary"]["test_records"], 1)
        routine = [record for record in spec["spec_records"] if record["entity_type"] == "internal_routine_contract"][0]
        self.assertEqual(routine["calling_convention"], "cdecl")
        self.assertEqual(routine["input_shape"]["seed"], "u32")
        self.assertEqual(routine["output_shape"]["score"], "u32")
        self.assertEqual(routine["evidence_source"], "dynamic_observation")
        self.assertNotIn("source_dirty_packet_label", payload)
        self.assertNotIn("source_packet_label", payload)
        self.assertNotIn(str(root), payload)

    def test_reviewed_template_with_private_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "behavior-observations",
                "leaky",
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_leaky",
                    "purpose_summary": "Bad template.",
                    "review_notes": [f"read {root}/private/result.json"],
                },
            )

            result = derive_clean_specs(corpus, root / "clean")
            spec = json.loads((root / "clean" / "specs.json").read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "fail")
        self.assertEqual(spec["summary"]["rejected_templates"], 1)
        self.assertIn("private path", result["rejected"][0]["reason"])

    def test_reviewed_template_with_raw_command_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "process-behavior-observations",
                "raw-command",
                {
                    "entity_type": "process_behavior_observation",
                    "public_label": "proc_raw_command",
                    "inputs": {"command": "wine /private/oracle.exe --json"},
                },
            )

            result = derive_clean_specs(corpus, root / "clean")

        self.assertEqual(result["status"], "fail")
        self.assertIn("private key", result["rejected"][0]["reason"])

    def test_reviewed_template_with_redacted_private_path_placeholder_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "internal-routine-contracts",
                "placeholder",
                {
                    "entity_type": "internal_routine_contract",
                    "public_label": "routine_placeholder",
                    "fixtures": ["[private path]"],
                },
            )

            result = derive_clean_specs(corpus, root / "clean")

        self.assertEqual(result["status"], "fail")
        self.assertIn("redacted private path placeholder", result["rejected"][0]["reason"])

    def test_cli_derives_clean_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "process-behavior-observations",
                "help",
                {
                    "entity_type": "process_behavior_observation",
                    "public_label": "proc_help",
                    "sanitized_name": "help_text",
                    "outputs": {"stdout_contains": ["usage: wincr-3d-game.exe"], "returncode": 0},
                },
            )
            stdout = StringIO()

            with redirect_stdout(stdout):
                code = main(
                    [
                        "derive-clean-specs",
                        "--corpus-dir",
                        str(corpus),
                        "--out-dir",
                        str(root / "clean"),
                    ],
                    prog="wincr",
                )
            payload = json.loads(stdout.getvalue())
            specs_markdown_exists = (root / "clean" / "specs.md").exists()

        self.assertEqual(code, 0)
        self.assertEqual(payload["clean_derivation"]["summary"]["test_records"], 1)
        self.assertTrue(specs_markdown_exists)

    def test_promote_clean_templates_marks_valid_templates_and_rejects_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = self._make_corpus(root)
            self._write_template(
                corpus,
                "behavior-observations",
                "clean",
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_clean",
                    "contract_id": "fixture.behavior",
                    "test_id": "seed-7",
                    "outputs": {"score": 42},
                },
                reviewed=False,
            )
            self._write_template(
                corpus,
                "behavior-observations",
                "leaky",
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_leaky",
                    "review_notes": [f"read {root}/private/result.json"],
                },
                reviewed=False,
            )

            result = promote_clean_templates(
                corpus,
                reviewer="unit-test",
                entity_types=("behavior_observation",),
            )
            promoted = json.loads(
                (corpus / "review" / "behavior-observations" / "clean" / "clean-template.json").read_text(
                    encoding="utf-8"
                )
            )
            leaky = json.loads(
                (corpus / "review" / "behavior-observations" / "leaky" / "clean-template.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["summary"]["promoted_templates"], 1)
        self.assertEqual(result["summary"]["rejected_templates"], 1)
        self.assertEqual(promoted["review_status"], "reviewed")
        self.assertEqual(promoted["taint_level"], "reviewed_public")
        self.assertEqual(promoted["publication_decision"], "publish")
        self.assertEqual(leaky["review_status"], "draft")

    def test_validate_clean_specs_accepts_complete_clean_spec_and_tests_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = self._clean_spec_fixture()
            tests = {
                "schema_version": 1,
                "format": spec["format"],
                "status": spec["status"],
                "generated_at": spec["generated_at"],
                "source_corpus": spec["source_corpus"],
                "summary": {"test_records": len(spec["test_records"])},
                "test_records": spec["test_records"],
            }
            spec_path = root / "specs.json"
            tests_path = root / "tests.json"
            write_json(spec_path, spec)
            write_json(tests_path, tests)

            result = validate_clean_specs(spec_path, tests_path)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["errors"], 0)
        self.assertEqual(result["summary"]["test_records"], 2)

    def test_validate_clean_specs_rejects_orphan_observation_and_missing_process_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = self._clean_spec_fixture()
            spec["test_records"][0]["contract_id"] = "missing.behavior"
            spec["test_records"][1]["inputs"].pop("argv")
            spec_path = root / "specs.json"
            write_json(spec_path, spec)

            result = validate_clean_specs(spec_path)

        self.assertEqual(result["status"], "fail")
        self.assertTrue(any("references unknown behavior contract" in error for error in result["errors"]))
        self.assertTrue(any("inputs.argv must be a list" in error for error in result["errors"]))

    def test_validate_clean_specs_rejects_unsatisfied_contract_coverage_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = self._clean_spec_fixture()
            spec["test_records"] = [
                record for record in spec["test_records"] if record.get("test_id") != "seed-7"
            ]
            spec["summary"]["test_records"] = len(spec["test_records"])
            spec["summary"]["templates"] = len(spec["spec_records"]) + len(spec["test_records"])
            spec_path = root / "specs.json"
            write_json(spec_path, spec)

            result = validate_clean_specs(spec_path)

        self.assertEqual(result["status"], "fail")
        self.assertTrue(any("coverage requirement json-seed-7" in error for error in result["errors"]))

    def test_cli_validates_clean_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec_path = root / "specs.json"
            write_json(spec_path, self._clean_spec_fixture())
            stdout = StringIO()

            with redirect_stdout(stdout):
                code = main(["validate-clean-specs", "--spec-json", str(spec_path)], prog="wincr")
            payload = json.loads(stdout.getvalue())

        self.assertEqual(code, 0)
        self.assertEqual(payload["clean_spec_validation"]["status"], "pass")

    def _make_corpus(self, root: Path) -> Path:
        corpus = root / "corpus"
        write_json(
            corpus / "manifest.json",
            {
                "format": "wincr-dirty-corpus-v2",
                "artifact_set_id": "test-dirty-corpus",
                "target": {"project_id": "test-target", "project_name": "Test Target"},
            },
        )
        return corpus

    def _write_template(self, corpus: Path, category: str, name: str, overrides: dict, *, reviewed: bool = True) -> None:
        payload = {
            "schema_version": 1,
            "source_dirty_packet_label": f"dirty_{name}",
            "source_dirty_packet_category": category,
            "entity_type": "behavior_observation",
            "public_label": f"public_{name}",
            "taint_level": "reviewed_public" if reviewed else "clean_candidate",
            "review_status": "reviewed" if reviewed else "draft",
            "evidence_labels": [f"dirty_{name}"],
            "sanitized_name": name,
            "purpose_summary": "Reviewed clean behavior.",
            "inputs": {},
            "outputs": {},
            "preconditions": [],
            "postconditions": [],
            "side_effects": [],
            "state_transitions": [],
            "fixtures": [],
            "test_vectors": [],
            "confidence": "high",
            "review_notes": [],
            "publication_decision": "publish" if reviewed else "not_reviewed",
        }
        payload.update(overrides)
        write_json(corpus / "review" / category / name / "clean-template.json", payload)

    def _clean_spec_fixture(self) -> dict:
        spec_record = {
            "schema_version": 1,
            "entity_type": "behavior_contract",
            "public_label": "behavior_fixture",
            "contract_id": "fixture.behavior",
            "version": "1",
            "title": "Fixture Behavior",
            "taint_level": "reviewed_public",
            "review_status": "reviewed",
            "publication_decision": "publish",
            "contract": {
                "format": "fixture-contract-v1",
                "coverage_requirements": {
                    "required_records": [
                        {
                            "id": "json-seed-7",
                            "entity_type": "behavior_observation",
                            "match": {
                                "contract_id": "fixture.behavior",
                                "test_id": "seed-7",
                                "status": "pass",
                            },
                        },
                        {
                            "id": "process-help",
                            "entity_type": "process_behavior_observation",
                            "match": {
                                "contract_id": "fixture.behavior",
                                "test_id": "help",
                                "inputs.argv": ["--help"],
                                "status": "pass",
                            },
                        },
                    ]
                },
            },
        }
        test_records = [
            {
                "schema_version": 1,
                "entity_type": "behavior_observation",
                "public_label": "obs_seed7",
                "contract_id": "fixture.behavior",
                "test_id": "seed-7",
                "status": "pass",
                "taint_level": "reviewed_public",
                "review_status": "reviewed",
                "publication_decision": "publish",
                "inputs": {"seed": 7},
                "outputs": {"score": 42},
            },
            {
                "schema_version": 1,
                "entity_type": "process_behavior_observation",
                "public_label": "proc_help",
                "contract_id": "fixture.behavior",
                "test_id": "help",
                "status": "pass",
                "taint_level": "reviewed_public",
                "review_status": "reviewed",
                "publication_decision": "publish",
                "inputs": {"argv": ["--help"]},
                "outputs": {"returncode": 0, "timed_out": False, "stdout": "usage\n"},
            },
        ]
        return {
            "schema_version": 1,
            "format": "wincr-clean-specs-v1",
            "status": "pass",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "source_corpus": {
                "source_kind": "review_corpus",
                "source_manifest_sha256": "0" * 64,
                "target": {"project_id": "fixture"},
            },
            "summary": {
                "templates": 3,
                "reviewed_records": 3,
                "skipped_templates": 0,
                "rejected_templates": 0,
                "spec_records": 1,
                "test_records": 2,
                "other_records": 0,
            },
            "spec_records": [spec_record],
            "test_records": test_records,
            "other_records": [],
        }


if __name__ == "__main__":
    unittest.main()
