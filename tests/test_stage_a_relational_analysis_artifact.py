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
    stage_a_generate_relational,
)
from spaghetti_extractor.cli import _exit_status
from spaghetti_extractor.util import sha256_file


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
            prepared = root / "prepared"
            monolithic = root / "monolithic"

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

            generated = stage_a_generate_relational(
                analysis=analysis,
                out=prepared,
            )
            self.assertEqual(generated["status"], "prepared")
            self.assertEqual(generated["acceptance"]["status"], "ready")
            self.assertEqual(
                generated["expected_final_theorem"],
                RELATIONAL_ACCEPTANCE_THEOREM,
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
