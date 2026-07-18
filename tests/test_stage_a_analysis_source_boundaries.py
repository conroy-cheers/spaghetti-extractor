import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class AnalysisSourceBoundaryTests(unittest.TestCase):
    repo = Path(__file__).parents[1]

    def _assert_clean_import(self, module: str, excluded: tuple[str, ...]) -> None:
        script = (
            f"import {module}\n"
            f"excluded = {excluded!r}\n"
            "loaded = sorted(name for name in excluded if name in __import__('sys').modules)\n"
            "raise SystemExit('unexpected imports: ' + ', '.join(loaded) if loaded else 0)\n"
        )
        env = {
            **os.environ,
            "PYTHONPATH": str(self.repo / "src"),
        }
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=self.repo,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_extraction_does_not_import_proof_generation_or_executor(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.extraction",
            (
                "spaghetti_extractor.relational.lean.definitions",
                "spaghetti_extractor.relational.executor",
            ),
        )

    def test_segment_analysis_does_not_import_proof_generation_or_executor(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.analyses.segments",
            (
                "spaghetti_extractor.relational.lean.definitions",
                "spaghetti_extractor.relational.executor",
            ),
        )

    def test_analysis_cli_does_not_import_downstream_proof_phases(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.analysis_cli",
            (
                "spaghetti_extractor.relational.analysis",
                "spaghetti_extractor.relational.analysis_artifact",
                "spaghetti_extractor.relational.build",
                "spaghetti_extractor.relational.executor",
                "spaghetti_extractor.relational.pipeline",
                "spaghetti_extractor.relational.proof_diagnostics",
                "spaghetti_extractor.relational.lean.acceptance",
                "spaghetti_extractor.relational.lean.composition",
                "spaghetti_extractor.relational.lean.definitions",
                "spaghetti_extractor.relational.lean.generation",
                "spaghetti_extractor.relational.lean.segments",
            ),
        )

    def test_pair_normalization_cli_does_not_import_pair_analysis(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.pair_normalization_cli",
            (
                "spaghetti_extractor.relational.analysis",
                "spaghetti_extractor.relational.analysis_artifact",
                "spaghetti_extractor.relational.build",
                "spaghetti_extractor.relational.pipeline",
                "spaghetti_extractor.relational.verdict",
                "spaghetti_extractor.relational.lean.acceptance",
                "spaghetti_extractor.relational.lean.generation",
            ),
        )

    def test_side_cli_does_not_import_pair_or_mapping_phases(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.side_cli",
            (
                "spaghetti_extractor.relational.analysis",
                "spaghetti_extractor.relational.analysis_artifact",
                "spaghetti_extractor.relational.mapping",
                "spaghetti_extractor.relational.pipeline",
                "spaghetti_extractor.relational.verdict",
            ),
        )

    def test_mapping_cli_does_not_import_extraction_or_pair_analysis(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.mapping_cli",
            (
                "spaghetti_extractor.relational.analysis",
                "spaghetti_extractor.relational.analysis_artifact",
                "spaghetti_extractor.relational.extraction",
                "spaghetti_extractor.relational.pipeline",
                "spaghetti_extractor.relational.verdict",
            ),
        )

    def test_compatibility_modules_reexport_moved_functions(self):
        from spaghetti_extractor.relational import executor
        from spaghetti_extractor.relational.lean import (
            analysis_source,
            compiler,
            definitions,
        )

        self.assertIs(
            definitions._copy_relational_kernel_sources,
            analysis_source._copy_relational_kernel_sources,
        )
        self.assertIs(
            definitions._lean_extraction_source,
            analysis_source._lean_extraction_source,
        )
        self.assertIs(
            definitions._lean_x87_state_only_pair,
            analysis_source._lean_x87_state_only_pair,
        )
        self.assertIs(executor._relational_cache_dir, compiler._relational_cache_dir)
        self.assertIs(executor._run_lean_relational, compiler._run_lean_relational)

    def test_analysis_kernel_copier_emits_only_decode_dependencies(self):
        from spaghetti_extractor.relational.lean.analysis_source import (
            _copy_relational_analysis_kernel_sources,
        )

        expected = {
            "Formal.lean",
            "ISAQualification.lean",
            "Relational.lean",
            "RelationalDecode.lean",
            "RelationalISAQualification.lean",
            "RelationalLoader.lean",
            "RelationalMachine.lean",
            "RelationalPEExecution.lean",
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "StageA"
            _copy_relational_analysis_kernel_sources(destination)

            self.assertEqual(
                {path.name for path in destination.iterdir()},
                expected,
            )


if __name__ == "__main__":
    unittest.main()
