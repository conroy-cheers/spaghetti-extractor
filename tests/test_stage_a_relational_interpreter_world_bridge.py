from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_world_bridge import (
    INTERPRETER_WORLD_BRIDGE_MODULE,
    InterpreterWorldBridgeGenerationError,
    InterpreterWorldBridgeSpec,
    relational_interpreter_world_bridge_source,
    write_relational_interpreter_world_bridge,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


def _spec(**overrides: str) -> InterpreterWorldBridgeSpec:
    values = {
        "binding_module": "StageA.GeneratedWorldNativeBindings",
        "namespace": "StageA.GeneratedWorldNativeAcceptance",
        "context": "Bindings.context",
        "graph": "Bindings.graph",
        "invariants": "Bindings.invariants",
        "reachability": "Bindings.reachability",
        "control": "Bindings.control",
        "launch": "Bindings.launch",
        "launch_checked": "Bindings.launchChecked",
        "original_program": "Bindings.originalProgram",
        "candidate_program": "Bindings.candidateProgram",
        "original_environment": "Bindings.originalEnvironment",
        "original_transfers": "Bindings.originalTransfers",
        "original_x87": "Bindings.originalX87",
        "program_table": "Bindings.programTable",
        "kernel_core": "Bindings.kernelCore",
        "program_coverage": "Bindings.programCoverage",
        "dispatch_semantics": "Bindings.dispatchSemantics",
        "sites": "Bindings.sites",
        "external_evidence": "Bindings.externalEvidence",
        "program_binding": "Bindings.programBinding",
        "candidate_x87_handler": "Bindings.candidateX87Handler",
        "candidate_x87_replay": "Bindings.candidateX87Replay",
        "candidate_root_rva": "Bindings.candidateRootRva",
        "candidate_root": "Bindings.candidateRoot",
        "launch_roots": "Bindings.launchRoots",
        "execution_relation": "Bindings.executionRelation",
        "roots_related": "Bindings.rootsRelated",
        "classify": "Bindings.classify",
        "ordinary_chunk": "Bindings.ordinaryChunk",
        "x87_chunk": "Bindings.x87Chunk",
        "opaque_external_chunk": "Bindings.opaqueExternalChunk",
        "quiescent_chunk": "Bindings.quiescentChunk",
    }
    values.update(overrides)
    return InterpreterWorldBridgeSpec(**values)


class StageARelationalInterpreterWorldBridgeGenerationTests(unittest.TestCase):
    def test_source_assembles_mixed_acceptance_only(self) -> None:
        source = relational_interpreter_world_bridge_source(_spec())

        self.assertIn("WorldNativeChunkComposition", source)
        self.assertIn("WorldNativeAcceptanceCertificate", source)
        self.assertIn(
            "ExactWorldNativeProgramsChunkObservationallyEquivalent", source
        )
        self.assertIn("kernelCore := Bindings.kernelCore", source)
        self.assertIn("candidateRootRva := Bindings.candidateRootRva", source)
        self.assertIn("externalEvidence := Bindings.externalEvidence", source)
        for field in (
            "executionRelation",
            "rootsRelated",
            "classify",
            "ordinaryChunk",
            "x87Chunk",
            "opaqueExternalChunk",
            "quiescentChunk",
        ):
            self.assertIn(f"{field} :=", source)
        self.assertNotIn("RoundTripChunkComposition", source)
        self.assertNotIn("PE32ProgramsChunkObservationallyEquivalent", source)
        self.assertNotIn("candidateEnvironment", source)
        self.assertNotIn("status", source)
        self.assertNotIn("by decide", source)

    def test_rejects_expressions_and_non_stage_a_modules(self) -> None:
        for overrides in (
            {"binding_module": "GeneratedWorldNativeBindings"},
            {"ordinary_chunk": "by exact fake"},
            {"theorem_name": "bad.name"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InterpreterWorldBridgeGenerationError):
                    relational_interpreter_world_bridge_source(_spec(**overrides))

    def test_writer_emits_the_mixed_bridge_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = write_relational_interpreter_world_bridge(
                temporary, _spec()
            )

            self.assertEqual(
                destination.name, f"{INTERPRETER_WORLD_BRIDGE_MODULE}.lean"
            )
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                relational_interpreter_world_bridge_source(_spec()),
            )

    def test_requirement_parameter_keeps_frontier_uninhabited(self) -> None:
        source = relational_interpreter_world_bridge_source(
            _spec(
                requirement_parameter="requirements",
                requirement_type="Bindings.RequiredTerms",
            )
        )

        self.assertIn(
            "variable (requirements : Bindings.RequiredTerms)", source
        )
        self.assertIn(
            "composition := generatedWorldNativeChunkComposition requirements",
            source,
        )
        self.assertIn(
            "worldNativeProgramsEquivalent "
            "(generatedWorldNativeAcceptanceCertificate requirements)",
            source,
        )
        self.assertIn(
            "worldNativeProgramsEquivalent_trace "
            "(generatedWorldNativeAcceptanceCertificate requirements)",
            source,
        )

    def test_rejects_partial_requirement_parameter(self) -> None:
        with self.assertRaises(InterpreterWorldBridgeGenerationError):
            relational_interpreter_world_bridge_source(
                _spec(requirement_parameter="requirements")
            )


class StageARelationalInterpreterWorldBridgeKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_mixed_composition_and_acceptance_compile_without_extra_axioms(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreterWorldBridge.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn(
            "executionRelation : WorldExecution -> NativeWorldExecution -> Prop",
            source,
        )
        self.assertIn(
            "candidatePath : NonemptyRelatedPath candidate.transitionSystem",
            source,
        )
        self.assertIn(
            "dispatches : RelationalWorld -> KernelDispatchRelation", source
        )
        self.assertIn("dispatchSemantics.operations world", source)
        self.assertIn("WorldNativeExecution.AtWorld world candidateBefore", source)
        self.assertIn("candidate.pe = context.candidatePe", source)
        self.assertIn("candidate.imports = context.candidateImports", source)
        self.assertIn("DirectExactCandidateNativeLaunchRoot candidate launch", source)
        self.assertNotIn("context.codeMap.get? launch.rootTargetId", source)
        self.assertNotIn("candidate.environment =", source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterWorldBridge"
            )
            (stage_a / "RelationalInterpreterWorldBridgeKernel.lean").write_text(
                _KERNEL_FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterWorldBridgeKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("WorldNativeChunkComposition.chunksRefine", output)
        self.assertIn("worldNativeProgramsEquivalent", output)
        self.assertIn("worldNativeProgramsEquivalent_trace", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterWorldBridge

namespace StageA.Relational.InterpreterWorldBridgeKernel

open StageA.Relational
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.InterpreterX87

variable {context : StaticProofContext}
variable {graph : RelationalProductGraph}
variable {invariants : ProductInvariantTable}
variable {reachability : RelationalProductReachabilityEvidence}
variable {control : ProductControlProfile}
variable {launch : PE32ConsoleLaunchV2}
variable {original : DecodedWorldProgram}
variable {candidate : ExactNativeWorldProgram}
variable {originalEnvironment : WorldExternalEnvironment}

example
    (launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore)
    (sites : List OpaqueLockstepCallSite)
    (externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment)
    (programBinding : ExactWorldNativeProgramBinding context original candidate
      originalEnvironment)
    (candidateX87Handler : CandidateReplayHandler)
    (candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler)
    (candidateRootRva : Nat)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva)
    (composition : WorldNativeChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87
      programTable kernelCore programCoverage dispatchSemantics sites
      originalEnvironment externalEvidence programBinding candidateX87Handler
      candidateX87Replay candidateRootRva candidateRoot) :
    ChunkedRelationalBisimulation original.pe32TransitionSystem
      candidate.transitionSystem composition.executionRelation
      (worldRelationalObservationsRelated context) :=
  composition.chunksRefine

example (world : RelationalWorld)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable)
    (dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore) :
    forall operation, KernelOperationRefinesUsing kernelCore.program kernelCore.abi
      (dispatchSemantics.dispatches world) operation :=
  dispatchSemantics.operations world

example
    (certificate : WorldNativeAcceptanceCertificate context graph invariants
      reachability control launch original candidate originalEnvironment) :
    ExactWorldNativeProgramsChunkObservationallyEquivalent context graph invariants
      reachability control launch original candidate originalEnvironment :=
  worldNativeProgramsEquivalent certificate

#print axioms WorldNativeChunkComposition.chunksRefine
#print axioms worldNativeProgramsEquivalent

end StageA.Relational.InterpreterWorldBridgeKernel
"""


if __name__ == "__main__":
    unittest.main()
