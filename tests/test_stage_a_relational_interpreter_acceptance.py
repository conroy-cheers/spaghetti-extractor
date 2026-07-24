from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_acceptance import (
    INTERPRETER_ACCEPTANCE_INVENTORY_FILENAME,
    INTERPRETER_ACCEPTANCE_MODULE,
    InterpreterAcceptanceGenerationError,
    InterpreterAcceptanceSpec,
    relational_interpreter_acceptance_inventory,
    relational_interpreter_acceptance_source,
    write_relational_interpreter_acceptance,
)


def _spec(**overrides: str) -> InterpreterAcceptanceSpec:
    values = {
        "binding_module": "StageA.GeneratedRoundTripBindings",
        "namespace": "StageA.GeneratedRoundTripAcceptance",
        "context": "Bindings.context",
        "graph": "Bindings.graph",
        "invariants": "Bindings.invariants",
        "reachability": "Bindings.reachability",
        "control": "Bindings.control",
        "launch": "Bindings.launch",
        "original_program": "Bindings.originalProgram",
        "candidate_program": "Bindings.candidateProgram",
        "original_environment": "Bindings.originalEnvironment",
        "candidate_environment": "Bindings.candidateEnvironment",
        "original_transfers": "Bindings.originalTransfers",
        "original_x87": "Bindings.originalX87",
        "program_table": "Bindings.programTable",
        "compiled_kernel": "Bindings.compiledKernel",
        "program_coverage": "Bindings.programCoverage",
        "opaque_sites": "Bindings.opaqueSites",
        "opaque_environment": "Bindings.opaqueEnvironment",
        "opaque_coverage": "Bindings.opaqueCoverage",
        "program_binding": "Bindings.programBinding",
        "program_surface": "Bindings.programSurface",
        "launch_roots": "Bindings.launchRoots",
        "launch_checked": "Bindings.launchChecked",
        "chunk_composition": "Bindings.chunkComposition",
    }
    values.update(overrides)
    return InterpreterAcceptanceSpec(**values)


class StageARelationalInterpreterAcceptanceGenerationTests(unittest.TestCase):
    def test_source_assembles_real_chunked_pe_theorem(self) -> None:
        source = relational_interpreter_acceptance_source(_spec())

        self.assertIn("RoundTripAcceptanceCertificate", source)
        self.assertIn("ExactPE32ProgramsChunkObservationallyEquivalent", source)
        self.assertIn("roundTripProgramsEquivalent", source)
        for field in (
            "originalTransfers",
            "originalX87",
            "programTable",
            "compiledKernel",
            "programCoverage",
            "opaqueCoverage",
            "opaqueEnvironment",
            "programBinding",
            "programSurface",
            "launchRoots",
            "launchChecked",
            "composition",
        ):
            self.assertIn(f"{field} :=", source)
        self.assertNotIn("by decide", source)
        self.assertNotIn('status := "pass"', source)

        kernel_source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterAcceptance.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("chunksDischargedByComponents", kernel_source)
        for component_case in (
            "classify",
            "ordinaryChunk",
            "x87Chunk",
            "opaqueExternalChunk",
            "quiescentChunk",
        ):
            self.assertIn(component_case, kernel_source)

    def test_inventory_names_every_typed_proof_frontier(self) -> None:
        inventory = relational_interpreter_acceptance_inventory(_spec())
        obligations = {row["id"]: row for row in inventory["proof_obligations"]}

        self.assertEqual(
            inventory["acceptance_proposition"],
            "ExactPE32ProgramsChunkObservationallyEquivalent",
        )
        self.assertEqual(
            set(obligations),
            {
                "exact-original-transfers",
                "exact-original-x87",
                "exact-compiled-program-table",
                "compiled-interpreter-kernel",
                "exact-program-inventory-coverage",
                "opaque-lockstep-environment",
                "exact-opaque-site-coverage",
                "exact-launch-roots",
                "checked-launch",
                "exact-decoded-program-binding",
                "exact-decoded-program-surface",
                "chunked-pe-simulation",
            },
        )
        self.assertIn(
            "compiled-interpreter-kernel",
            obligations["chunked-pe-simulation"]["depends_on"],
        )
        self.assertIn(
            "exact-program-inventory-coverage",
            obligations["chunked-pe-simulation"]["depends_on"],
        )
        self.assertIn(
            "exact-decoded-program-binding",
            obligations["chunked-pe-simulation"]["depends_on"],
        )
        self.assertIn(
            "exact-decoded-program-surface",
            obligations["chunked-pe-simulation"]["depends_on"],
        )
        self.assertTrue(
            all(
                row["discharged_only_by"] == "Lean type checking"
                for row in obligations.values()
            )
        )
        self.assertTrue(all("status" not in row for row in obligations.values()))
        self.assertTrue(inventory["closed_acceptance"])
        self.assertIsNone(inventory["required_parameter"])

    def test_parameterized_frontier_is_not_reported_as_closed_acceptance(self) -> None:
        spec = _spec(
            requirement_parameter="requirements",
            requirement_type="Bindings.RequiredTerms",
            context="requirements.context",
        )
        source = relational_interpreter_acceptance_source(spec)
        inventory = relational_interpreter_acceptance_inventory(spec)

        self.assertIn(
            "(requirements : Bindings.RequiredTerms)",
            source,
        )
        self.assertIn(
            "roundTripProgramsEquivalent "
            "(generatedRoundTripAcceptanceCertificate requirements)",
            source,
        )
        self.assertFalse(inventory["closed_acceptance"])
        self.assertEqual(
            inventory["required_parameter"],
            {
                "name": "requirements",
                "lean_type": "Bindings.RequiredTerms",
                "closure_requirement": "a checked Lean term inhabiting this type",
            },
        )

    def test_rejects_lean_expressions_and_non_stage_a_modules(self) -> None:
        for overrides in (
            {"binding_module": "GeneratedRoundTripBindings"},
            {"compiled_kernel": "by exact fake"},
            {"theorem_name": "bad.name"},
            {"requirement_parameter": "requirements"},
            {"requirement_type": "Bindings.RequiredTerms"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InterpreterAcceptanceGenerationError):
                    relational_interpreter_acceptance_source(_spec(**overrides))

    def test_writer_emits_source_and_obligation_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = write_relational_interpreter_acceptance(root, _spec())

            source_path = root / "StageA" / f"{INTERPRETER_ACCEPTANCE_MODULE}.lean"
            self.assertTrue(source_path.is_file())
            self.assertTrue(
                (root / INTERPRETER_ACCEPTANCE_INVENTORY_FILENAME).is_file()
            )
            self.assertEqual(
                inventory["source_sha256"],
                relational_interpreter_acceptance_inventory(_spec())[
                    "source_sha256"
                ],
            )


class StageARelationalInterpreterAcceptanceKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_component_certificates_construct_real_acceptance_theorem(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreterAcceptance.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in source_root.glob("*.lean"):
                shutil.copyfile(module, stage_a / module.name)
            (stage_a / "RelationalInterpreterAcceptanceKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterAcceptanceKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_mismatched_program_table_and_kernel_are_rejected(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in source_root.glob("*.lean"):
                shutil.copyfile(module, stage_a / module.name)
            (stage_a / "RelationalInterpreterAcceptanceMismatch.lean").write_text(
                _MISMATCHED_COMPONENT_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterAcceptanceMismatch"
            )

        self.assertEqual(result["status"], "failed", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("programTableB", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterAcceptance

namespace StageA.Relational.InterpreterAcceptanceKernel

open StageA.Relational
open StageA.Relational.InterpreterAcceptance

variable {context : StaticProofContext}
variable {graph : RelationalProductGraph}
variable {invariants : ProductInvariantTable}
variable {reachability : RelationalProductReachabilityEvidence}
variable {control : ProductControlProfile}
variable {launch : PE32ConsoleLaunchV2}
variable {original candidate : DecodedWorldProgram}
variable {originalEnvironment candidateEnvironment : WorldExternalEnvironment}

example
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (compiledKernel : ExactCompiledInterpreterKernel context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (opaqueSites : List OpaqueLockstepCallSite)
    (opaqueCoverage : ExactOpaqueProgramCoverage context original candidate opaqueSites)
    (opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
      originalEnvironment candidateEnvironment)
    (programBinding : ExactRoundTripProgramBinding context original candidate
      originalEnvironment candidateEnvironment)
    (programSurface : ExactRoundTripDecodedProgramSurface context graph invariants
      reachability control original candidate)
    (launchRoots : ExactRoundTripLaunchRoots context launch)
    (launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch)
    (composition : RoundTripChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87 programTable
      compiledKernel programCoverage opaqueSites opaqueCoverage originalEnvironment
      candidateEnvironment programBinding opaqueEnvironment) :
    ExactPE32ProgramsChunkObservationallyEquivalent context graph invariants
      reachability control launch original candidate := by
  let certificate : RoundTripAcceptanceCertificate context graph invariants
      reachability control launch original candidate originalEnvironment
      candidateEnvironment := {
    originalTransfers
    originalX87
    programTable
    compiledKernel
    programCoverage
    opaqueSites
    opaqueCoverage
    opaqueEnvironment
    programBinding
    programSurface
    launchRoots
    launchChecked
    composition
  }
  exact roundTripProgramsEquivalent certificate

#print axioms roundTripProgramsEquivalent

end StageA.Relational.InterpreterAcceptanceKernel
"""


_MISMATCHED_COMPONENT_FIXTURE = r"""import StageA.RelationalInterpreterAcceptance

namespace StageA.Relational.InterpreterAcceptanceMismatch

open StageA.Relational
open StageA.Relational.InterpreterAcceptance

variable {context : StaticProofContext}
variable (programTableA programTableB : ExactCompiledProgramTable context)
variable (compiledKernelA : ExactCompiledInterpreterKernel context programTableA)

example : ExactCompiledInterpreterKernel context programTableB :=
  compiledKernelA

end StageA.Relational.InterpreterAcceptanceMismatch
"""


if __name__ == "__main__":
    unittest.main()
