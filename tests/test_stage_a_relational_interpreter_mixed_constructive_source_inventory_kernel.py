from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_constructive_source_inventory import (
    CheckedKernelEntryBinding,
    ConstructiveClassifierTerms,
    ConstructiveSourceInventorySpec,
    ConstructiveSourceRuleBinding,
    ExactSemanticSourceBinding,
    build_constructive_source_inventory_plan,
    relational_interpreter_mixed_constructive_source_inventory_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
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


def _kernel_spec() -> ConstructiveSourceInventorySpec:
    sources = tuple(
        ExactSemanticSourceBinding(
            name=f"source{index}",
            target_id=index,
            source_rva=0x1000 + index * 0x10,
            record_index=index,
            source_term=f"requirements.source{index}",
            target_id_exact=f"requirements.source{index}TargetIdExact",
            source_rva_exact=f"requirements.source{index}RvaExact",
            record_at_index_exact=f"requirements.source{index}RecordExact",
        )
        for index in range(4)
    )
    entries = (
        CheckedKernelEntryBinding(
            "lookup",
            "programLookup",
            0x2000,
            "requirements.lookupEntryExact",
        ),
        CheckedKernelEntryBinding(
            "invoke",
            "invokeCall",
            0x2100,
            "requirements.invokeEntryExact",
        ),
        CheckedKernelEntryBinding(
            "run",
            "runFunction",
            0x2200,
            "requirements.runEntryExact",
        ),
    )
    return ConstructiveSourceInventorySpec(
        binding_module="StageA.ConstructiveSourceInventoryFixture",
        parameter_name="requirements",
        parameter_type="StageA.ConstructiveSourceInventoryFixture.Requirements",
        namespace="StageA.GeneratedRelational.ConstructiveSourceInventory",
        terms=ConstructiveClassifierTerms(
            original_context="requirements.originalContext",
            original_authority="requirements.originalAuthority",
            launch_profile="requirements.launchProfile",
            original_root="requirements.originalRoot",
            reachability="requirements.reachability",
            original_program="requirements.originalProgram",
            candidate="requirements.candidate",
            candidate_authority="requirements.candidateAuthority",
            compiled_program="requirements.program",
            kernel_abi="requirements.abi",
            kernel_dispatches="requirements.dispatches",
            relation_contract="requirements.contract",
            candidate_root_rva="requirements.candidateRootRva",
            launch_root_target_id_exact="requirements.launchRootTargetIdExact",
            candidate_root_rva_exact="requirements.candidateRootRvaExact",
            candidate_record_count_exact="requirements.candidateRecordCountExact",
            reachability_target_ids_exact=("requirements.reachabilityTargetIdsExact"),
        ),
        candidate_root_rva=0x3000,
        launch_root_target_id=0,
        candidate_record_count=4,
        expected_target_ids=(0, 1, 2, 3),
        expected_operations=("programLookup", "invokeCall", "runFunction"),
        sources=sources,
        entries=entries,
        rules=(
            ConstructiveSourceRuleBinding("source0", "launch"),
            ConstructiveSourceRuleBinding("source1", "semantic_transfer", "lookup"),
            ConstructiveSourceRuleBinding("source2", "external_operation", "invoke"),
            ConstructiveSourceRuleBinding(
                "source3",
                "external_boundary",
                "run",
                candidate_rva=0x2300,
            ),
        ),
    )


class StageARelationalInterpreterMixedConstructiveSourceInventoryKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_inventory_compiles_and_audits(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        generated = relational_interpreter_mixed_constructive_source_inventory_source(
            build_constructive_source_inventory_plan(_kernel_spec())
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedConstructiveSourceClassifier",
            )
            (stage_a / "ConstructiveSourceInventoryFixture.lean").write_text(
                _BINDING_FIXTURE,
                encoding="utf-8",
            )
            (
                stage_a
                / "GeneratedRelationalInterpreterMixedConstructiveSourceInventory.lean"
            ).write_text(generated, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle=(
                    "GeneratedRelationalInterpreterMixedConstructiveSourceInventory"
                ),
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for declaration in (
            "generatedCandidateRecordSourceRvasUnique",
            "generatedSourceTargetIdsUnique",
            "generatedReachabilityTargetIdsExact",
            "generatedSourceRvasUnique",
            "generatedRecordIndicesUnique",
            "generatedRecordIndicesInBounds",
            "generatedRuleSourceTargetIdsExact",
            "generatedRulesCoverReachability",
            "generatedRuleMatchKeysExact",
            "generatedRuleMatchKeysUnique",
            "generatedRuleSourceTargetIdsUnique",
            "generatedActualRuleMatchKeysUnique",
            "generatedConstructiveMixedKernelSourceClassifier",
            "GeneratedConstructiveSourceResidual.invariantHolds",
        ):
            self.assertIn(declaration, output)
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_inventory_rejects_shorter_reachability_proof(self) -> None:
        generated = relational_interpreter_mixed_constructive_source_inventory_source(
            build_constructive_source_inventory_plan(_kernel_spec())
        )
        broken_fixture = _BINDING_FIXTURE.replace(
            "reachability.targetIds = [0, 1, 2, 3]",
            "reachability.targetIds = [0, 1, 2]",
        )
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedConstructiveSourceClassifier",
            )
            (stage_a / "ConstructiveSourceInventoryFixture.lean").write_text(
                broken_fixture,
                encoding="utf-8",
            )
            (
                stage_a
                / "GeneratedRelationalInterpreterMixedConstructiveSourceInventory.lean"
            ).write_text(generated, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle=(
                    "GeneratedRelationalInterpreterMixedConstructiveSourceInventory"
                ),
            )

        self.assertEqual(result["status"], "failed", result)
        self.assertIn("reachabilityTargetIdsExact", result["stdout"])


_BINDING_FIXTURE = r"""import StageA.RelationalInterpreterMixedConstructiveSourceClassifier

namespace StageA.ConstructiveSourceInventoryFixture

open StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

structure Requirements where
  originalContext : OriginalDecodedStaticContext
  originalAuthority : ExactOriginalDecodedAuthority originalContext
  launchProfile : PE32ConsoleLaunchV2
  originalRoot :
    DirectExactOriginalDecodedLaunchRoot originalContext launchProfile
  reachability : ExactOriginalDecodedReachability originalContext
    originalAuthority launchProfile originalRoot
  originalProgram : DecodedWorldProgram
  candidate : ExactNativeWorldProgram
  candidateAuthority : ExactNativeCandidateAuthority candidate
  program : CompiledKernelProgram
  abi : KernelABIRelation
  dispatches : KernelDispatchRelation
  contract : MixedRelationContract
  candidateRootRva : Nat
  launchRootTargetIdExact : launchProfile.rootTargetId = 0
  candidateRootRvaExact : candidateRootRva = 12288
  candidateRecordCountExact :
    candidateAuthority.semanticRecords.length = 4
  reachabilityTargetIdsExact :
    reachability.targetIds = [0, 1, 2, 3]
  source0 : ExactOriginalSemanticSource originalContext originalAuthority
    launchProfile originalRoot reachability candidate candidateAuthority
  source0TargetIdExact : source0.targetId = 0
  source0RvaExact : source0.source.target.rva = 4096
  source0RecordExact :
    candidateAuthority.semanticRecords[0]? = some source0.record
  source1 : ExactOriginalSemanticSource originalContext originalAuthority
    launchProfile originalRoot reachability candidate candidateAuthority
  source1TargetIdExact : source1.targetId = 1
  source1RvaExact : source1.source.target.rva = 4112
  source1RecordExact :
    candidateAuthority.semanticRecords[1]? = some source1.record
  source2 : ExactOriginalSemanticSource originalContext originalAuthority
    launchProfile originalRoot reachability candidate candidateAuthority
  source2TargetIdExact : source2.targetId = 2
  source2RvaExact : source2.source.target.rva = 4128
  source2RecordExact :
    candidateAuthority.semanticRecords[2]? = some source2.record
  source3 : ExactOriginalSemanticSource originalContext originalAuthority
    launchProfile originalRoot reachability candidate candidateAuthority
  source3TargetIdExact : source3.targetId = 3
  source3RvaExact : source3.source.target.rva = 4144
  source3RecordExact :
    candidateAuthority.semanticRecords[3]? = some source3.record
  lookupEntryExact :
    program.functionEntry? KernelOperation.programLookup.role = some 8192
  invokeEntryExact :
    program.functionEntry? KernelOperation.invokeCall.role = some 8448
  runEntryExact :
    program.functionEntry? KernelOperation.runFunction.role = some 8704

end StageA.ConstructiveSourceInventoryFixture
"""


if __name__ == "__main__":
    unittest.main()
