from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_semantic_operation_component import (
    INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE,
    InterpreterMixedSemanticOperationComponentSpec,
    MixedSemanticOperationComponentTerms,
    build_mixed_semantic_operation_component_plan,
    relational_interpreter_mixed_semantic_operation_component_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


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


def _spec() -> InterpreterMixedSemanticOperationComponentSpec:
    return InterpreterMixedSemanticOperationComponentSpec(
        binding_module="StageA.MixedSemanticOperationComponentFixture",
        namespace="StageA.Generated.MixedSemanticOperationComponent",
        parameter_name="requirements",
        parameter_type=(
            "StageA.MixedSemanticOperationComponentFixture.Requirements"
        ),
        terms=MixedSemanticOperationComponentTerms(
            original_context="requirements.originalContext",
            original_authority="requirements.originalAuthority",
            launch="requirements.launch",
            original_root="requirements.originalRoot",
            reachability="requirements.reachability",
            original_program="requirements.originalProgram",
            candidate="requirements.candidate",
            candidate_authority="requirements.candidateAuthority",
            relation_contract="requirements.contract",
            invariant="requirements.invariant",
            compiled_program="requirements.program",
            kernel_abi="requirements.abi",
            kernel_dispatches="requirements.dispatches",
            classifier="requirements.classifier",
            source_binding_factory="requirements.sourceBindingFactory",
            semantic_evidence_factory=(
                "requirements.semanticEvidenceFactory"
            ),
            external_operation_evidence_factory=(
                "requirements.externalOperationEvidenceFactory"
            ),
        ),
    )


class StageARelationalInterpreterMixedSemanticOperationComponentKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_bridge_and_generated_factories_compile_with_approved_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        generated = (
            relational_interpreter_mixed_semantic_operation_component_source(
                build_mixed_semantic_operation_component_plan(_spec())
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedSemanticOperationComponent",
            )
            (stage_a / "MixedSemanticOperationComponentFixture.lean").write_text(
                _BINDING_FIXTURE,
                encoding="utf-8",
            )
            (stage_a / f"{INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE}.lean").write_text(
                generated,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle=INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE,
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "generatedMixedSemanticOperationComponent",
            "generatedMixedExternalOperationComponent",
            "generatedSemanticChunkFactory",
            "generatedExternalOperationChunkFactory",
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


_BINDING_FIXTURE = r"""import StageA.RelationalInterpreterMixedSemanticOperationComponent

namespace StageA.MixedSemanticOperationComponentFixture

open StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

structure Requirements where
  originalContext : OriginalDecodedStaticContext
  originalAuthority : ExactOriginalDecodedAuthority originalContext
  launch : PE32ConsoleLaunchV2
  originalRoot :
    DirectExactOriginalDecodedLaunchRoot originalContext launch
  reachability : ExactOriginalDecodedReachability originalContext
    originalAuthority launch originalRoot
  originalProgram : DecodedWorldProgram
  candidate : ExactNativeWorldProgram
  candidateAuthority : ExactNativeCandidateAuthority candidate
  contract : MixedRelationContract
  invariant : MixedExecutionInvariant reachability.targetIds contract
  program : CompiledKernelProgram
  abi : KernelABIRelation
  dispatches : KernelDispatchRelation
  classifier : MixedKernelRuntimeSourceClassifier originalContext
    originalAuthority launch originalRoot reachability candidate
    candidateAuthority program 0 invariant
  sourceBindingFactory : forall source :
      ExactOriginalSemanticSource originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority,
    ExactOriginalSemanticTransferBinding originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority source
  semanticEvidenceFactory : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entryRva candidateBefore)
      (entryExact :
        program.functionEntry? operation.role = some entryRva)
      (classified :
        classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .semanticTransfer source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    CheckedMixedSemanticOperationEvidence originalProgram candidate
      candidateAuthority contract invariant program abi dispatches
      source.source.target.rva source.record operation entryRva originalBefore
      candidateBefore
      (classifier.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .semanticTransfer source operation entryRva originalAtSource
          candidateAtEntry entryExact)
      beforeRelated classified
  externalOperationEvidenceFactory : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entryRva candidateBefore)
      (entryExact :
        program.functionEntry? operation.role = some entryRva)
      (classified :
        classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalOperation source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    CheckedMixedSemanticOperationEvidence originalProgram candidate
      candidateAuthority contract invariant program abi dispatches
      source.source.target.rva source.record operation entryRva originalBefore
      candidateBefore
      (classifier.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .externalOperation source operation entryRva originalAtSource
          candidateAtEntry entryExact)
      beforeRelated classified

end StageA.MixedSemanticOperationComponentFixture
"""


if __name__ == "__main__":
    unittest.main()
