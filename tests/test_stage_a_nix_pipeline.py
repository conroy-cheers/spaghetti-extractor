import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from spaghetti_extractor.isa_kernel_qualification import (
    QualificationStatus,
    SemanticKernelBinding,
)
from spaghetti_extractor.relational import build as relational_build
from spaghetti_extractor.relational import nix_pipeline
from spaghetti_extractor.relational.report import NixBuildReport
from spaghetti_extractor.relational.schema import (
    RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_bytes, write_json


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

    def test_report_parser_rejects_legacy_and_disagreeing_verdicts(self) -> None:
        with self.assertRaisesRegex(
            StageAInputError,
            "stage-a-relational-nix-build-v1",
        ):
            NixBuildReport.parse({
                "format": "stage-a-relational-verdict-v1",
                "status": "pass",
                "verdict": "pass",
            })
        with self.assertRaisesRegex(StageAInputError, "disagree"):
            NixBuildReport.parse({
                "format": "stage-a-relational-nix-build-v1",
                "status": "pass",
                "verdict": "incomplete",
            })

    def test_report_parser_requires_complete_checked_pass_evidence(self) -> None:
        theorem = RELATIONAL_FINAL_ACCEPTANCE_THEOREM
        report = NixBuildReport.parse({
            "format": "stage-a-relational-nix-build-v1",
            "status": "pass",
            "verdict": "pass",
            "expected_final_theorem": theorem,
            "checks": {"graph": True, "proof": True},
            "lean_audit": {
                "status": "checked",
                "lean_trust": 0,
                "theorem": theorem,
            },
        })
        self.assertTrue(report.declares_checked_pass)

    def test_full_build_fails_before_nix_without_exact_isa_qualification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "prepared"
            prepared.mkdir()
            out = root / "out"
            graph = {
                "nodes": [],
                "acceptance": {"status": "ready"},
            }
            with (
                mock.patch.object(
                    relational_build,
                    "_validate_prepared_relational",
                    return_value=graph,
                ),
                mock.patch.object(
                    relational_build, "_relational_nix_evaluator"
                ) as evaluator,
            ):
                result = relational_build.stage_a_build_relational(
                    prepared=prepared,
                    out=out,
                )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(
                result["diagnostic"]["category"],
                "isa_kernel_qualification_missing",
            )
            self.assertFalse(
                result["checks"]["exact_isa_semantic_kernel_qualified"]
            )
            self.assertFalse(result["checks"]["nix_graph_built"])
            evaluator.assert_not_called()
            prerequisite = json.loads(
                (out / "isa-kernel-prerequisite.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(prerequisite["trust"]["proof_authority"])
            self.assertFalse(prerequisite["trust"]["closes_stage_a_proof"])

    def test_exact_selection_ignores_unrelated_qualification_frontiers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "prepared"
            prepared.mkdir()
            qualification_path = root / "qualification.json"
            semantic_kernel_path = root / "kernel.json"
            write_json(prepared / "isa-requirements.json", {})
            write_json(qualification_path, {})
            write_json(semantic_kernel_path, {})
            semantic_kernel = SimpleNamespace(
                id="kernel",
                decoder_sha256="1" * 64,
                semantics_sha256="2" * 64,
                lean_version="4.19.0",
            )
            qualification = SimpleNamespace(
                status=QualificationStatus.VETOED
            )
            selection = SimpleNamespace(
                status=QualificationStatus.QUALIFIED
            )
            with (
                mock.patch.object(
                    relational_build,
                    "_validate_isa_semantic_kernel_source",
                    return_value=semantic_kernel,
                ),
                mock.patch.object(
                    relational_build,
                    "parse_kernel_qualification",
                    return_value=qualification,
                ),
                mock.patch.object(
                    relational_build,
                    "select_isa_kernel_qualification_for_inventory",
                    side_effect=(selection, selection),
                ),
                mock.patch.object(
                    relational_build,
                    "serialize_kernel_selection",
                    side_effect=({"side": "original"}, {"side": "candidate"}),
                ),
            ):
                prerequisite = (
                    relational_build._evaluate_isa_kernel_prerequisite(
                        prepared=prepared,
                        graph={},
                        qualification_path=qualification_path,
                        semantic_kernel_path=semantic_kernel_path,
                    )
                )

            self.assertEqual(prerequisite["status"], "qualified")
            self.assertEqual(
                prerequisite["qualification_status"], "vetoed"
            )
            self.assertTrue(all(prerequisite["checks"].values()))

    def test_semantic_kernel_bundle_uses_the_declared_hash_domains(
        self,
    ) -> None:
        kernel_modules = tuple(dict.fromkeys(
            (
                *relational_build._ISA_KERNEL_SOURCE_MODULES,
                *relational_build._ISA_KERNEL_SEMANTICS_MODULES,
            )
        ))
        source_hashes = {
            module: f"{index:x}" * 64
            for index, module in enumerate(
                kernel_modules, start=1
            )
        }
        nodes = [
            {
                "id": module,
                "modules": [module],
                "source_sha256": sha256_bytes(
                    source_hashes[module].encode("ascii")
                ),
                "semantic_id": f"{index + 5:x}" * 64,
                "semantic_recipe_version":
                    "stage-a-lean-standalone-recipe-v1",
            }
            for index, module in enumerate(
                kernel_modules
            )
        ]
        by_id = {row["id"]: row for row in nodes}
        semantics_rows = [
            {
                "id": module,
                "semantic_id": by_id[module]["semantic_id"],
                "semantic_recipe_version":
                    by_id[module]["semantic_recipe_version"],
                "source_sha256": by_id[module]["source_sha256"],
            }
            for module in relational_build._ISA_KERNEL_SEMANTICS_MODULES
        ]
        semantics_rows.sort(key=lambda row: row["id"])
        semantics_sha256 = sha256_bytes(
            (
                json.dumps(
                    semantics_rows,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
        )
        binding = SemanticKernelBinding(
            id="kernel",
            decoder_sha256=by_id["ISAQualification"]["semantic_id"],
            semantics_sha256=semantics_sha256,
            lean_version="Lean test",
        )
        graph = {
            "lean": {"version": "Lean test"},
            "modules": {
                module: {"source_sha256": source_hashes[module]}
                for module in relational_build._ISA_KERNEL_SOURCE_MODULES
            },
        }
        bundle = {"lean_version": "Lean test", "nodes": nodes}

        relational_build._validate_isa_semantic_kernel_bundle(
            binding=binding,
            bundle=bundle,
            graph=graph,
        )
        corrupted_graph = json.loads(json.dumps(graph))
        corrupted_graph["modules"]["X87"]["source_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            StageAInputError, "does not use the qualified X87 source"
        ):
            relational_build._validate_isa_semantic_kernel_bundle(
                binding=binding,
                bundle=bundle,
                graph=corrupted_graph,
            )

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
                    isa_kernel_qualification=root / "qualification.json",
                    isa_semantic_kernel=root / "kernel.json",
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
