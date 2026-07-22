import contextlib
import io
import json

from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.analysis_artifact import (
    RELATIONAL_ANALYSIS_MANIFEST,
    RELATIONAL_ANALYSIS_REQUIRED_FILES,
    copy_relational_analysis,
    validate_relational_analysis,
    write_relational_analysis_manifest,
)
from spaghetti_extractor.relational.pipeline import (
    stage_a_analyze_relational,
    stage_a_discover_relational_proposals,
    stage_a_generate_relational,
)
from spaghetti_extractor.relational.analysis import (
    stage_a_assemble_relational_analysis,
)
from spaghetti_extractor.relational.proposal_artifact import (
    validate_relational_proposal,
)
from spaghetti_extractor.relational.schema import (
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.relational.register_dataflow_problem_cli import (
    main as compile_register_dataflow_problem_main,
)
from spaghetti_extractor.relational.register_dataflow_aggregate import (
    aggregate_register_dataflow_pack_results,
)
from spaghetti_extractor.relational.register_dataflow_packs import (
    project_register_dataflow_packs,
)
from spaghetti_extractor.relational.register_dataflow_solver import (
    solve_register_dataflow_pack,
)
from spaghetti_extractor.relational.register_dataflow_summary import (
    summarize_register_dataflow_pack_result,
)
from spaghetti_extractor.relational.register_replay import (
    stage_a_replay_register_dataflow,
)
from spaghetti_extractor.relational.semantic_products import (
    stage_a_produce_semantic_products,
)
from spaghetti_extractor.relational.memory_products import (
    stage_a_produce_memory_products,
)
from spaghetti_extractor.relational.composition_products import (
    stage_a_produce_composition_products,
)
from spaghetti_extractor.cli import _exit_status
from spaghetti_extractor.util import sha256_file, write_json


class StageARelationalAnalysisArtifactTests(StageARelationalTestBase):
    def _write_minimal_analysis_tree(self, root: Path) -> None:
        for relative in RELATIONAL_ANALYSIS_REQUIRED_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                b"original" if relative == "artifacts/original.pe"
                else b"candidate" if relative == "artifacts/candidate.pe"
                else b"{}\n"
            )

    def test_manifest_copy_is_content_addressed_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            copied = root / "copied"
            self._write_minimal_analysis_tree(analysis)
            payload = write_relational_analysis_manifest(
                analysis,
                original_sha256=sha256_file(
                    analysis / "artifacts" / "original.pe"
                ),
                candidate_sha256=sha256_file(
                    analysis / "artifacts" / "candidate.pe"
                ),
            )
            self.assertEqual(payload["status"], "analyzed")
            manifest = validate_relational_analysis(analysis)
            copy_relational_analysis(analysis, copied)
            self.assertEqual(validate_relational_analysis(copied), manifest)
            self.assertTrue((copied / RELATIONAL_ANALYSIS_MANIFEST).is_file())

            (copied / "relational-proof-ir.json").write_text(
                '{"tampered":true}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(StageAInputError, "hash mismatch"):
                validate_relational_analysis(copied)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for extraction")
    def test_analyzed_direct_loop_generates_same_acceptance_surface(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            analysis = root / "analysis"
            assembled_analysis = root / "assembled-analysis"
            proposal = root / "proposal"
            prepared = root / "prepared"
            monolithic = root / "monolithic"

            proposed = stage_a_discover_relational_proposals(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=proposal,
            )
            self.assertEqual(
                proposed["format"], "stage-a-relational-proposal-closure-v1"
            )
            validate_relational_proposal(proposal)
            self.assertFalse((proposal / "lean").exists())
            self.assertFalse((proposal / "relational-product-graph.json").exists())

            proposal_problem = root / "proposal-register-problem.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    compile_register_dataflow_problem_main([
                        "--original", str(proposal / "artifacts" / "original.pe"),
                        "--candidate", str(proposal / "artifacts" / "candidate.pe"),
                        "--seed",
                        str(
                            proposal
                            / "relational-register-dataflow-problem-seed.json"
                        ),
                        "--contract", str(proposal / "relation-contract.json"),
                        "--decoded-behaviors",
                        str(proposal / "relational-decoded-behaviors.json"),
                        "--out", str(proposal_problem),
                    ]),
                    0,
                )
            problem_payload = json.loads(
                proposal_problem.read_text(encoding="utf-8")
            )
            projection = project_register_dataflow_packs(
                graph_payload=problem_payload["graph"],
                transfer_table_payload=None,
                transfer_programs_payload=problem_payload["transfer_programs"],
                expected_original_sha256=proposed["original_sha256"],
                expected_candidate_sha256=proposed["candidate_sha256"],
            )
            pack_results = {}
            for pack_id in projection.manifest["topological_pack_ids"]:
                pack = projection.inputs[pack_id]
                pack_results[pack_id] = solve_register_dataflow_pack(
                    pack_payload=pack,
                    predecessor_payloads=[
                        summarize_register_dataflow_pack_result(
                            pack_results[predecessor]
                        )
                        for predecessor in pack["predecessor_ids"]
                    ],
                    transfer_context_payload=projection.transfer_context,
                )
            aggregate = aggregate_register_dataflow_pack_results(
                manifest_payload=projection.manifest,
                result_payloads=list(pack_results.values()),
            )
            aggregate_path = root / "register-aggregate.json"
            write_json(aggregate_path, aggregate)
            register_replay = root / "register-replay"
            replayed = stage_a_replay_register_dataflow(
                proposal=proposal,
                register_dataflow_aggregate=aggregate_path,
                out=register_replay,
            )
            self.assertEqual(
                replayed["status"],
                "untrusted_proposal_requires_lean_replay",
            )
            semantic_products = root / "semantic-products"
            semantics = stage_a_produce_semantic_products(
                proposal=proposal,
                out=semantic_products,
            )
            self.assertEqual(
                semantics["status"],
                "untrusted_proposal_requires_lean_replay",
            )
            memory_products = root / "memory-products"
            memory = stage_a_produce_memory_products(
                proposal=proposal,
                register_replay=register_replay,
                out=memory_products,
            )
            self.assertEqual(
                memory["status"],
                "untrusted_proposal_requires_lean_replay",
            )
            composition_products = root / "composition-products"
            composition = stage_a_produce_composition_products(
                proposal=proposal,
                register_replay=register_replay,
                semantic_products=semantic_products,
                memory_products=memory_products,
                out=composition_products,
            )
            self.assertEqual(
                composition["status"],
                "untrusted_proposal_requires_lean_replay",
            )
            assembled = stage_a_assemble_relational_analysis(
                proposal=proposal,
                register_replay=register_replay,
                semantic_products=semantic_products,
                memory_products=memory_products,
                composition_products=composition_products,
                out=assembled_analysis,
            )
            self.assertEqual(assembled["status"], "analyzed")
            validate_relational_analysis(assembled_analysis)

            analyzed = stage_a_analyze_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=analysis,
            )
            self.assertEqual(analyzed["status"], "analyzed")
            self.assertEqual(_exit_status(analyzed), 0)
            self.assertFalse((analysis / "lean").exists())
            self.assertFalse((analysis / "certificates").exists())
            validate_relational_analysis(analysis)
            assembled_manifest = validate_relational_analysis(assembled_analysis)
            monolithic_manifest = validate_relational_analysis(analysis)
            self.assertEqual(
                [
                    relative
                    for relative in sorted(monolithic_manifest.files)
                    if assembled_manifest.files.get(relative)
                        != monolithic_manifest.files[relative]
                ],
                [],
            )

            regenerated_problem = root / "regenerated-register-problem.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    compile_register_dataflow_problem_main([
                        "--original",
                        str(analysis / "artifacts" / "original.pe"),
                        "--candidate",
                        str(analysis / "artifacts" / "candidate.pe"),
                        "--seed",
                        str(
                            analysis
                            / "relational-register-dataflow-problem-seed.json"
                        ),
                        "--contract",
                        str(analysis / "relation-contract.json"),
                        "--decoded-behaviors",
                        str(analysis / "relational-decoded-behaviors.json"),
                        "--out", str(regenerated_problem),
                    ]),
                    0,
                )
            self.assertEqual(
                json.loads(regenerated_problem.read_text(encoding="utf-8"))[
                    "graph"
                ],
                json.loads(
                    (
                        analysis
                        / "relational-register-program-dataflow-graph.json"
                    ).read_text(encoding="utf-8")
                ),
            )
            self.assertEqual(
                json.loads(regenerated_problem.read_text(encoding="utf-8"))[
                    "transfer_programs"
                ],
                json.loads(
                    (
                        analysis / "relational-register-transfer-programs.json"
                    ).read_text(encoding="utf-8")
                ),
            )

            generated = stage_a_generate_relational(
                analysis=analysis,
                out=prepared,
            )
            self.assertEqual(generated["status"], "prepared")
            self.assertEqual(generated["acceptance"]["status"], "ready")
            self.assertEqual(
                generated["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            self.assertTrue((prepared / "module-graph.json").is_file())
            validate_relational_analysis(prepared)
            _validate_prepared_relational(prepared)

            combined = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=monolithic,
            )
            self.assertEqual(combined, generated)
            for relative in (
                "relational-analysis-manifest.json",
                "whole-program-acceptance.json",
                "composition-progress.json",
                "module-graph.json",
                "prepared-proof.json",
            ):
                self.assertEqual(
                    sha256_file(prepared / relative),
                    sha256_file(monolithic / relative),
                    relative,
                )


if __name__ == "__main__":
    unittest.main()
