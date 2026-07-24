from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel_loop import (
    RelationalInterpreterKernelLoopGenerationError,
    build_relational_interpreter_kernel_loop_plan,
    relational_interpreter_kernel_loop_source,
)


def _block(entry: int, *successors: int) -> dict[str, object]:
    return {
        "entry_rva": entry,
        "instructions": [{"rva": entry, "bytes": "90", "mnemonic": "nop"}],
        "successors": list(successors),
    }


def _kernel(
    functions: list[dict[str, object]],
    *,
    issues: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-relational-interpreter-kernel-plan-v2",
        "candidate": {"pe_sha256": "a" * 64, "size": 4096},
        "kernel_functions": functions,
        "issues": issues or [],
    }


def _function(
    *blocks: dict[str, object], role: str = "interpreterStep"
) -> dict[str, object]:
    return {
        "role": role,
        "rva_start": blocks[0]["entry_rva"],
        "rva_end": 0x2000,
        "blocks": list(blocks),
    }


class StageARelationalInterpreterKernelLoopTests(unittest.TestCase):
    def _plan(self, payload: dict[str, object]):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "kernel.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return build_relational_interpreter_kernel_loop_plan(path)

    def test_recovers_exact_dominator_back_edge_and_natural_body(self) -> None:
        plan = self._plan(
            _kernel(
                [
                    _function(
                        _block(0x1000, 0x1010),
                        _block(0x1010, 0x1020, 0x1040),
                        _block(0x1020, 0x1030),
                        _block(0x1030, 0x1010),
                        _block(0x1040),
                    )
                ]
            )
        )

        self.assertEqual(plan.loop_count, 1)
        loop = plan.functions[0].loops[0]
        self.assertEqual((loop.latch_rva, loop.header_rva), (0x1030, 0x1010))
        self.assertEqual(loop.body_entries, (0x1010, 0x1020, 0x1030))
        self.assertEqual(
            [(edge.source, edge.target) for edge in loop.entry_edges],
            [(0x1000, 0x1010)],
        )
        self.assertEqual(
            [(edge.source, edge.target) for edge in loop.exit_edges],
            [(0x1010, 0x1040)],
        )
        payload = plan.payload()
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["structural_status"], "pending_lean_check")
        self.assertEqual(payload["counts"]["exact_cfg_back_edges"], 1)
        self.assertEqual(payload["counts"]["semantic_frontiers"], 5)
        self.assertFalse(payload["acceptance_authority"])
        self.assertTrue(
            all(
                frontier["status"] == "pending_lean_proof"
                for frontier in payload["semantic_frontiers"]
            )
        )

    def test_address_order_alone_does_not_create_a_back_edge(self) -> None:
        plan = self._plan(
            _kernel(
                [
                    _function(
                        _block(0x1100, 0x1000),
                        _block(0x1000),
                    )
                ]
            )
        )
        self.assertEqual(plan.loop_count, 0)
        self.assertEqual(plan.payload()["semantic_status"], "not_applicable")

    def test_reports_irreducible_entry_instead_of_certifying_it(self) -> None:
        plan = self._plan(
            _kernel(
                [
                    _function(
                        _block(0x1000, 0x1010, 0x1020),
                        _block(0x1010, 0x1020),
                        _block(0x1020, 0x1030),
                        _block(0x1030, 0x1010),
                    )
                ]
            )
        )
        self.assertIn(
            "irreducible_kernel_cycle",
            {issue["code"] for issue in plan.issues},
        )
        self.assertEqual(plan.payload()["structural_status"], "incomplete")

    def test_rejects_unrooted_or_duplicate_cfg_data(self) -> None:
        plan = self._plan(_kernel([_function(_block(0x1000), _block(0x1010))]))
        self.assertIn(
            "kernel_loop_unreachable_cfg_nodes",
            {issue["code"] for issue in plan.issues},
        )

        with self.assertRaisesRegex(
            RelationalInterpreterKernelLoopGenerationError, "duplicate block entry"
        ):
            self._plan(_kernel([_function(_block(0x1000), _block(0x1000))]))

    def test_generated_source_exposes_goals_not_semantic_status_theorems(self) -> None:
        plan = self._plan(
            _kernel(
                [
                    _function(
                        _block(0x1000, 0x1010),
                        _block(0x1010, 0x1010),
                    )
                ]
            )
        )
        source = relational_interpreter_kernel_loop_source(plan)
        self.assertIn("GeneratedInterpreterKernelLoopStructuralGoal", source)
        self.assertIn("GeneratedInterpreterKernelLoopExactCFGGoal", source)
        self.assertIn("GeneratedInterpreterKernelLoopSemanticGoal", source)
        self.assertIn("SemanticallyInductive", source)
        self.assertIn("GeneratedInterpreterKernelTargetClassificationGoal", source)
        self.assertIn("GeneratedInterpreterKernelCFGExecutionGoal", source)
        self.assertIn("GeneratedInterpreterKernelOperationGoal", source)
        self.assertIn("GeneratedInterpreterCompiledKernelGoal", source)
        self.assertIn("KernelOperationCFGCertificate", source)
        self.assertIn("CompiledKernelCFGCertificate", source)
        self.assertIn("KernelOperationCFGCertificate.refines certificate", source)
        self.assertNotIn("native_decide", source)
        self.assertNotIn("pending_lean_proof", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_indirect_control_is_an_explicit_fail_closed_frontier(self) -> None:
        plan = self._plan(
            _kernel(
                [_function(_block(0x1000))],
                issues=[
                    {
                        "code": "unsupported_indirect_kernel_call",
                        "function_role": "helper 7",
                        "rva_start": 0x1010,
                        "rva_end": 0x1012,
                        "message": "requires a target classifier",
                    }
                ],
            )
        )
        payload = plan.payload()
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["counts"]["indirect_control_sites"], 1)
        frontier = payload["semantic_frontiers"][0]
        self.assertEqual(frontier["family"], "kernel_indirect_target_classification")
        self.assertEqual(frontier["location"]["rva_start"], 0x1010)
        self.assertEqual(frontier["status"], "pending_lean_proof")

    def test_rejects_stale_format_and_invalid_module_name(self) -> None:
        with self.assertRaisesRegex(
            RelationalInterpreterKernelLoopGenerationError, "unsupported"
        ):
            self._plan({"format": "old", "candidate": {}, "kernel_functions": []})
        plan = self._plan(_kernel([_function(_block(0x1000))]))
        with self.assertRaisesRegex(
            RelationalInterpreterKernelLoopGenerationError, "qualified StageA"
        ):
            relational_interpreter_kernel_loop_source(
                plan, kernel_module="Generated.Bad"
            )


class StageARelationalInterpreterKernelLoopLeanTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generic_kernel_and_fixture_compile(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        imports = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            pending = ["RelationalInterpreterKernelLoop"]
            copied: set[str] = set()
            while pending:
                module = pending.pop()
                if module in copied:
                    continue
                text = (source_root / f"{module}.lean").read_text(encoding="utf-8")
                (stage_a / f"{module}.lean").write_text(text, encoding="utf-8")
                pending.extend(imports.findall(text))
                copied.add(module)
            (stage_a / "RelationalInterpreterKernelLoopFixture.lean").write_text(
                _LEAN_FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelLoopFixture"
            )
        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_operation_goal_compiles_without_acceptance_shortcut(self) -> None:
        plan = StageARelationalInterpreterKernelLoopTests()._plan(
            _kernel(
                [
                    _function(
                        _block(0x1000, 0x1010),
                        _block(0x1010, 0x1010),
                    )
                ]
            )
        )
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        imports = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            pending = ["RelationalInterpreterKernelLoop"]
            copied: set[str] = set()
            while pending:
                module = pending.pop()
                if module in copied:
                    continue
                text = (source_root / f"{module}.lean").read_text(encoding="utf-8")
                (stage_a / f"{module}.lean").write_text(text, encoding="utf-8")
                pending.extend(imports.findall(text))
                copied.add(module)
            (stage_a / "GeneratedRelationalInterpreterKernel.lean").write_text(
                _GENERATED_KERNEL_STUB, encoding="utf-8"
            )
            (stage_a / "GeneratedRelationalInterpreterKernelLoop.lean").write_text(
                relational_interpreter_kernel_loop_source(plan), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInterpreterKernelLoop"
            )
        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_GENERATED_KERNEL_STUB = r"""import StageA.RelationalInterpreterKernel

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Relational.InterpreterKernel

def generatedCompiledKernelProgram : CompiledKernelProgram := { functions := [] }

end StageA.GeneratedRelational.InterpreterKernel
"""


_LEAN_FIXTURE = r"""import StageA.RelationalInterpreterKernelLoop

namespace StageA.Relational.InterpreterKernelLoopFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelLoop

def block (entry : Nat) (successors : List Nat) : KernelBlock := {
  entryRva := entry
  instructions := [{ rva := entry, bytes := [144] }]
  successors := successors
}

def function : KernelFunction := {
  role := .interpreterStep
  hint := "fixture"
  span := { start := 4096, size := 3 }
  bytes := [144, 144, 144]
  sha256 := ""
  blocks := [block 4096 [4097], block 4097 [4098], block 4098 [4097]]
  padding := []
  loops := []
  frame := {
    required := false, pushRva := 0, setupRva := 0,
    teardownRvas := [], returnRvas := []
  }
}

def shape : KernelLoopShapeCertificate := {
  headerRva := 4097
  latchRva := 4098
  bodyEntries := [4097, 4098]
}

def program : CompiledKernelProgram := { functions := [function] }

def inventory : KernelLoopInventory := {
  functions := [{
    functionIndex := 0
    functionEntryRva := 4096
    loops := [shape]
  }]
}

example : exactBackEdges function = [{ source := 4098, target := 4097 }] := by
  native_decide

example : shape.checked function = true := by
  native_decide

example : inventory.checked program = true := by
  native_decide

example : ({ functions := [] } : KernelLoopInventory).checked program = false := by
  native_decide

example (contract : KernelLoopContract) :
    WellFounded contract.RankRelation :=
  contract.rankRelation_wellFounded

def controlFunction : KernelFunction := {
  function with
  span := { start := 8192, size := 3 }
  blocks := [block 8192 [8208, 8224], block 8208 [], block 8224 []]
}

def controlProgram : CompiledKernelProgram := { functions := [controlFunction] }

def targetInventory : KernelIndirectTargetInventory := {
  classifiers := [{ siteRva := 8192, kind := .call, targetRvas := [8208] }]
}

def jumpTargetInventory : KernelIndirectTargetInventory := {
  classifiers := [{ siteRva := 8192, kind := .jump, targetRvas := [8208] }]
}

def emptyTargetInventory : KernelIndirectTargetInventory := { classifiers := [] }

example (pe : PE32) :
    KernelCFGEdgeKind.direct.checked { source := 8192, target := 8208 }
      controlProgram pe targetInventory = true := by
  rfl

example (pe : PE32) :
    (KernelCFGEdgeKind.internalCall 8224 (pe.imageBase + 8224)).checked
      { source := 8192, target := 8208 } controlProgram pe targetInventory = true := by
  simp [KernelCFGEdgeKind.checked, programBlockAt?, controlProgram,
    controlFunction, function, block, CompiledKernelProgram.blockEntries,
    KernelFunction.blockEntries]

example (pe : PE32) :
    KernelCFGEdgeKind.internalReturn.checked { source := 8208, target := 8224 }
      controlProgram pe targetInventory = true := by
  rfl

example (pe : PE32) :
    (KernelCFGEdgeKind.indirectCall 8192 8224
      (pe.imageBase + 8224)).checked
      { source := 8192, target := 8208 } controlProgram pe targetInventory = true := by
  simp [KernelCFGEdgeKind.checked, programBlockAt?, controlProgram,
    controlFunction, function, block, CompiledKernelProgram.blockEntries,
    KernelFunction.blockEntries, KernelIndirectTargetInventory.allowsRva,
    targetInventory]

example (pe : PE32) :
    (KernelCFGEdgeKind.indirectJump 8192).checked
      { source := 8192, target := 8208 } controlProgram pe jumpTargetInventory = true := by
  rfl

example (pe : PE32) :
    (KernelCFGEdgeKind.indirectJump 8192).checked
      { source := 8192, target := 8208 } controlProgram pe targetInventory = false := by
  rfl

example (pe : PE32) :
    (KernelCFGEdgeKind.indirectJump 8192).checked
      { source := 8192, target := 8208 } controlProgram pe emptyTargetInventory = false := by
  rfl

example {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {abi : KernelABIRelation}
    {targets : KernelIndirectTargetInventory} {loops : KernelLoopInventory}
    {contracts : Nat -> Nat -> KernelLoopContract} {operation : KernelOperation}
    (certificate : KernelOperationCFGCertificate program pe imports environment abi
      targets loops contracts operation) :
    KernelOperationRefines program pe imports environment abi operation :=
  certificate.refines

example {binding : KernelArtifactBinding} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {abi : KernelABIRelation} {targets : KernelIndirectTargetInventory}
    {loops : KernelLoopInventory} {contracts : Nat -> Nat -> KernelLoopContract}
    (certificate : CompiledKernelCFGCertificate binding program pe imports
      environment abi targets loops contracts) :
    CompiledKernelRefinement binding program pe imports environment abi :=
  certificate.refines

end StageA.Relational.InterpreterKernelLoopFixture
"""


if __name__ == "__main__":
    unittest.main()
