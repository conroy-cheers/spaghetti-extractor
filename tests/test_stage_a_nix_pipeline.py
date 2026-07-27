import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.relational import nix_pipeline
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


class StageANixPipelineTests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, Path, Path, Path]:
        original = root / "original.exe"
        candidate = root / "candidate.exe"
        contract = root / "relation.json"
        evaluator = root / "analysis.nix"
        original.write_bytes(b"original")
        candidate.write_bytes(b"candidate")
        contract.write_text("{}\n", encoding="utf-8")
        evaluator.write_text("{}\n", encoding="utf-8")
        return original, candidate, contract, evaluator

    def test_expression_uses_explicit_empty_nixpkgs_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, evaluator = self._inputs(root)
            expression = nix_pipeline._relational_analysis_nix_expression(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                evaluator=evaluator,
                flake_root=root,
            )
        self.assertIn("config = {};", expression)

    def test_realization_requires_exactly_one_output_and_sanitizes_host_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, evaluator = self._inputs(root)
            (root / "flake.lock").write_text("{}\n", encoding="utf-8")
            process = mock.Mock(
                returncode=0,
                stdout=json.dumps([{"outputs": {}}, {"outputs": {}}]),
                stderr="",
            )
            with (
                mock.patch.object(
                    nix_pipeline,
                    "_relational_analysis_nix_evaluator",
                    return_value=evaluator,
                ),
                mock.patch.object(
                    nix_pipeline,
                    "_find_relational_flake_root",
                    return_value=root,
                ),
                mock.patch.object(
                    nix_pipeline,
                    "_relational_nix_build_command",
                    return_value=["nix", "build"],
                ),
                mock.patch.object(
                    nix_pipeline,
                    "_content_addressed_derivations_requested",
                    return_value=False,
                ),
                mock.patch.dict(
                    os.environ,
                    {"NIXPKGS_CONFIG": "/unreadable/config.nix"},
                ),
                mock.patch.object(
                    nix_pipeline.subprocess, "run", return_value=process
                ) as run,
            ):
                with self.assertRaisesRegex(
                    StageAInputError, "malformed relational preparation provenance"
                ):
                    nix_pipeline._realize_relational_preparation(
                        original=original,
                        candidate=candidate,
                        relation_contract=contract,
                        flake=None,
                        builders_file=None,
                        builder_trusted_public_keys_file=None,
                    )
            self.assertNotIn("NIXPKGS_CONFIG", run.call_args.kwargs["env"])

    def test_prepare_validates_then_copies_a_writable_prepared_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "store" / "report" / "relational-v3"
            prepared.mkdir(parents=True)
            write_json(
                prepared / "prepared-proof.json",
                {
                    "format": "stage-a-prepared-relational-v2",
                    "status": "prepared",
                },
            )
            prepared.chmod(0o555)
            out = root / "out"
            provenance = {
                "format": "stage-a-relational-nix-preparation-v1",
                "status": "prepared",
            }
            with (
                mock.patch.object(
                    nix_pipeline,
                    "_realize_relational_preparation",
                    return_value=(prepared, provenance),
                ),
            ):
                result = nix_pipeline.stage_a_prepare_relational_nix(
                    original=root / "unused-original",
                    candidate=root / "unused-candidate",
                    relation_contract=root / "unused-contract",
                    out=out,
                )
            self.assertEqual(
                result["format"],
                "stage-a-relational-nix-preparation-result-v1",
            )
            self.assertEqual(result["status"], "prepared")
            self.assertEqual(
                result["prepared_format"], "stage-a-prepared-relational-v2"
            )
            self.assertTrue(os.access(out, os.W_OK))
            self.assertTrue((out / "nix-preparation-provenance.json").is_file())

    def test_prove_return_value_matches_persisted_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "prepared"
            prepared.mkdir()
            out = root / "out"
            provenance = {
                "format": "stage-a-relational-nix-preparation-v1",
                "status": "prepared",
            }

            def build(**kwargs):
                kwargs["out"].mkdir()
                result = {
                    "format": "stage-a-relational-nix-build-v1",
                    "status": "incomplete",
                    "verdict": "incomplete",
                }
                write_json(kwargs["out"] / "verdict.json", result)
                return result

            with (
                mock.patch.object(
                    nix_pipeline,
                    "_realize_relational_preparation",
                    return_value=(prepared, provenance),
                ),
                mock.patch.object(
                    nix_pipeline, "stage_a_build_relational", side_effect=build
                ),
            ):
                result = nix_pipeline.stage_a_prove_relational_nix(
                    original=root / "unused-original",
                    candidate=root / "unused-candidate",
                    relation_contract=root / "unused-contract",
                    out=out,
                )
            persisted = json.loads(
                (out / "verdict.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result, persisted)
            self.assertEqual(
                len(result["nix_preparation_provenance_sha256"]), 64
            )


if __name__ == "__main__":
    unittest.main()
