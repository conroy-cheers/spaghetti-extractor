from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_mixed_fused_semantic_evidence import (
    GnuHelloMixedFusedSemanticEvidenceSpec,
    generate_gnu_hello_mixed_fused_semantic_evidence,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    relational_interpreter_normalization_bundle_sources,
)
from spaghetti_extractor.relational.lean.interpreter_semantic_refinement import (
    relational_interpreter_semantic_refinement_bundle_sources,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from tests.test_stage_a_relational_interpreter_normalization_kernel import (
    _FIXTURE,
    _PROGRAM_FIXTURE,
    _lea_row,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(
    r"depends on axioms: \[([^\]]*)\]", re.MULTILINE
)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


class StageARelationalInterpreterMixedFusedSemanticEvidenceAdapterKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_adapter_compiles_with_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        module = "RelationalInterpreterMixedFusedSemanticEvidenceAdapter"
        adapter_source = (source_root / f"{module}.lean").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "structure CheckedCandidateKernelDispatchAtBefore",
            adapter_source,
        )
        self.assertIn(
            "candidateBefore.machine? = some beforeMachine",
            adapter_source,
        )
        self.assertIn(
            "candidate.transitionSystem candidateBefore",
            adapter_source,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(root, bundle=module)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "CheckedFusedOriginalSemanticTransferBinding.sequentialFusion",
            "CheckedCandidateKernelOperationReplay.pathFromCandidateBefore",
            "CheckedOrdinaryMixedSemanticOperationInput.toEvidence",
        ):
            self.assertIn(declaration, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_binding_and_ordinary_wrapper_elaborate(self) -> None:
        row = _lea_row()
        refinement_sources = (
            relational_interpreter_semantic_refinement_bundle_sources(
                [row],
                pe_module="StageA.GeneratedNormalizationProgramFixture",
                shard_size=1,
            )
        )
        normalization_sources = (
            relational_interpreter_normalization_bundle_sources(
                [row],
                source_module="StageA.GeneratedNormalizationProgramFixture",
                pe_name="StageA.GeneratedRelational.originalPe",
                semantic_refinement_module=(
                    "StageA.GeneratedInterpreterSemanticRefinementBundle"
                ),
                shard_size=1,
            )
        )
        generated = generate_gnu_hello_mixed_fused_semantic_evidence(
            [row],
            GnuHelloMixedFusedSemanticEvidenceSpec(
                pe_module="StageA.GeneratedNormalizationProgramFixture",
                shard_size=1,
            ),
        )
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedFusedSemanticEvidenceAdapter",
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterAcceptance",
            )
            (stage_a / "RelationalInterpreterNormalizationKernel.lean").write_text(
                _FIXTURE,
                encoding="utf-8",
            )
            (stage_a / "GeneratedNormalizationProgramFixture.lean").write_text(
                _PROGRAM_FIXTURE,
                encoding="utf-8",
            )
            for sources in (
                refinement_sources,
                normalization_sources,
                generated.sources,
            ):
                for module, source in sources.items():
                    (stage_a / f"{module}.lean").write_text(
                        source, encoding="utf-8"
                    )
            result = _run_lean_relational(
                root,
                bundle=generated.inventory["target"],
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertIn(
            "generatedCheckedFusedOriginalSemanticBinding0",
            (
                generated.sources[
                    "GeneratedGnuHelloMixedFusedSemanticEvidenceShard0000"
                ]
            ),
        )
        self.assertIn(
            "generatedCheckedMixedOrdinarySemanticEvidence0",
            (
                generated.sources[
                    "GeneratedGnuHelloMixedFusedSemanticEvidenceShard0000"
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
