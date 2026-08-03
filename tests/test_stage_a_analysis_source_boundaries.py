import os
import re
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

    def test_removed_host_orchestration_modules_stay_removed(self):
        package = self.repo / "src" / "spaghetti_extractor"
        for path in (
            package / "stage_a_relational.py",
            package / "relational" / "executor.py",
            package / "relational" / "proof_diagnostics.py",
            package / "relational" / "verdict.py",
        ):
            self.assertFalse(path.exists(), path)

    def test_extraction_does_not_import_proof_generation_or_executor(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.extraction",
            (
                "spaghetti_extractor.relational.lean.definitions",
            ),
        )

    def test_segment_analysis_does_not_import_proof_generation_or_executor(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.analyses.segments",
            (
                "spaghetti_extractor.relational.lean.definitions",
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
                "spaghetti_extractor.relational.lean.acceptance",
                "spaghetti_extractor.relational.lean.generation",
            ),
        )

    def test_region_facts_cli_does_not_import_global_or_proof_phases(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.region_facts_cli",
            (
                "spaghetti_extractor.relational.analysis",
                "spaghetti_extractor.relational.analysis_artifact",
                "spaghetti_extractor.relational.build",
                "spaghetti_extractor.relational.pipeline",
                "spaghetti_extractor.relational.lean.acceptance",
                "spaghetti_extractor.relational.lean.composition",
                "spaghetti_extractor.relational.lean.definitions",
                "spaghetti_extractor.relational.lean.generation",
                "spaghetti_extractor.relational.lean.segments",
            ),
        )

    def test_proof_preparation_does_not_import_isa_oracle_tooling(self):
        self._assert_clean_import(
            "spaghetti_extractor.relational.preparation_cli",
            (
                "spaghetti_extractor.isa_cli",
                "spaghetti_extractor.isa_campaign",
                "spaghetti_extractor.isa_catalog",
                "spaghetti_extractor.isa_catalog_enrichment",
                "spaghetti_extractor.isa_conformance",
                "spaghetti_extractor.isa_corpus_generator",
                "spaghetti_extractor.isa_kernel_qualification",
                "spaghetti_extractor.isa_side_adapter",
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
            ),
        )

    def test_lean_compatibility_modules_reexport_moved_functions(self):
        from spaghetti_extractor.relational.lean import (
            analysis_source,
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

    def test_analysis_kernel_copier_emits_closed_analysis_dependencies(self):
        from spaghetti_extractor.relational.lean.analysis_source import (
            _copy_relational_analysis_kernel_sources,
        )

        expected = {
            "X87.lean",
            "RelationalX87.lean",
            "Formal.lean",
            "RelationalX87Decode.lean",
            "ISAQualification.lean",
            "RelationalDecode.lean",
            "RelationalISAQualification.lean",
            "RelationalLoader.lean",
            "RelationalFiniteIndex.lean",
            "RelationalMachine.lean",
            "RelationalMemory.lean",
            "Relational.lean",
            "RelationalPEMachineStep.lean",
            "RelationalPEExecution.lean",
            "RelationalX87Machine.lean",
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "StageA"
            _copy_relational_analysis_kernel_sources(destination)

            self.assertEqual(
                {path.name for path in destination.iterdir()},
                expected,
            )

            for source in destination.glob("*.lean"):
                for imported in re.findall(
                    r"(?m)^import StageA\.([A-Za-z0-9_]+)$",
                    source.read_text(encoding="utf-8"),
                ):
                    self.assertIn(
                        f"{imported}.lean",
                        expected,
                        f"{source.name} imports an omitted analysis-kernel module",
                    )

    def test_proof_kernel_inventory_is_closed(self):
        from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES

        expected = set(RELATIONAL_KERNEL_MODULES)
        source_root = self.repo / "src" / "spaghetti_extractor" / "lean" / "StageA"
        for module in RELATIONAL_KERNEL_MODULES:
            source = source_root / f"{module}.lean"
            self.assertTrue(source.is_file(), source)
            for imported in re.findall(
                r"(?m)^import StageA\.([A-Za-z0-9_]+)$",
                source.read_text(encoding="utf-8"),
            ):
                self.assertIn(
                    imported,
                    expected,
                    f"{source.name} imports an omitted proof-kernel module",
                )


if __name__ == "__main__":
    unittest.main()
