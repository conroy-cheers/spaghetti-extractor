from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelClosedCallTreeTests(
    unittest.TestCase
):
    def test_generic_closed_call_tree_compiles_without_bad_axioms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelClosedCallTree",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelClosedCallTree"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "CheckedInterpreterStepDerivation.toAbstract",
            "CheckedRunFunctionDerivation.toAbstractRunFunction",
            (
                "CheckedInvokeCallDerivation."
                "toAbstractKernelTransition"
            ),
            (
                "CheckedInterpreterStepDerivation."
                "toAbstractKernelTransition"
            ),
            (
                "CheckedRunFunctionDerivation."
                "toAbstractKernelTransition"
            ),
            "checkedInvokeCall_iff_abstractKernelTransition",
            "checkedInterpreterStep_iff_abstractKernelTransition",
            "checkedRunFunction_iff_abstractKernelTransition",
            (
                "FiniteCheckedRunFunctionEvidence."
                "toCheckedRunFunctionDerivation"
            ),
            (
                "FiniteCheckedInvokeCallEvidence."
                "toCheckedInvokeCallDerivation"
            ),
        ):
            self.assertIn(theorem, output)

    def test_rank_free_finite_evidence_constructs_checked_run_and_invoke(
        self,
    ) -> None:
        fixture = """import StageA.RelationalInterpreterKernelClosedCallTree

namespace StageA.RankFreeClosedCallTreeFixture

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree

variable (records : List ProgramRecord) (environment : Environment)
variable (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
variable (sourceRva : Nat) (state : InterpreterMachine)
variable (lookupExact :
  lookupProgramRecord records sourceRva = none)
variable (abstractStep :
  AbstractInterpreterStepDerivation records environment resolveCodeTarget
    sourceRva state none)

def unavailableRun :
    AbstractRunFunction records environment resolveCodeTarget sourceRva state
      { status := .unimplemented, state := state } :=
  .unavailable sourceRva state abstractStep

def unavailableEvidence :
    FiniteCheckedRunFunctionEvidence records environment resolveCodeTarget
      sourceRva state { status := .unimplemented, state := state }
      (unavailableRun records environment resolveCodeTarget sourceRva state
        abstractStep) :=
  .unavailable sourceRva state abstractStep
    (.lookupUnavailable sourceRva state lookupExact)

def unavailableChecked :
    CheckedRunFunctionDerivation records environment resolveCodeTarget sourceRva
      state { status := .unimplemented, state := state } :=
  (unavailableEvidence records environment resolveCodeTarget sourceRva state
    lookupExact abstractStep).toCheckedRunFunctionDerivation

variable (event : CallEvent) (kindExact : event.kind = .internal)
variable (calleeLookupExact :
  lookupProgramRecord records event.targetRva.toNat = none)
variable (calleeAbstractStep :
  AbstractInterpreterStepDerivation records environment resolveCodeTarget
    event.targetRva.toNat state none)

def internalRun :
    AbstractRunFunction records environment resolveCodeTarget
      event.targetRva.toNat state
      { status := .unimplemented, state := state } :=
  .unavailable event.targetRva.toNat state calleeAbstractStep

def internalEvidence :
    FiniteCheckedInvokeCallEvidence records environment resolveCodeTarget event
      state { status := .unimplemented, state := state } :=
  .internal event state { status := .unimplemented, state := state } kindExact
    (internalRun records environment resolveCodeTarget state event
      calleeAbstractStep)
    (.unavailable event.targetRva.toNat state calleeAbstractStep
      (.lookupUnavailable event.targetRva.toNat state calleeLookupExact))

def internalChecked :
    CheckedInvokeCallDerivation records environment resolveCodeTarget event state
      { status := .unimplemented, state := state } :=
  (internalEvidence records environment resolveCodeTarget state event kindExact
    calleeLookupExact calleeAbstractStep).toCheckedInvokeCallDerivation

#print axioms unavailableChecked
#print axioms internalChecked

end StageA.RankFreeClosedCallTreeFixture
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelClosedCallTree",
            )
            (stage_a / "RankFreeClosedCallTreeFixture.lean").write_text(
                fixture, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RankFreeClosedCallTreeFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("unavailableChecked", output)
        self.assertIn("internalChecked", output)
        self.assertNotIn("sorryAx", output)

    def test_step_calls_have_an_explicit_invoke_trace_edge(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelClosedCallTree.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "mutual",
            "CheckedInterpreterStepDerivation",
            "CheckedRunFunctionDerivation",
            "CheckedInvokeCallDerivation",
            "CheckedInterpreterCallTraceEdge",
            "invocation : CheckedInvokeCallDerivation",
            "notCall : forall callIndex, action != .call callIndex",
            "event state (environment.invokeCall event state)",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "GNU",
            "0x",
        ):
            self.assertNotIn(forbidden, source)

        rank_free = source.split(
            "/-! ## Rank-free construction from finite nested evidence", 1
        )[1].split(
            "/-! ## Well-founded construction from exact semantic records", 1
        )[0]
        for required in (
            "FiniteCheckedRunFunctionEvidence",
            "FiniteCheckedInvokeCallEvidence",
            "run : AbstractRunFunction",
            "targetExact : resolveCodeTarget event.targetRva = some target",
            "toCheckedRunFunctionDerivation",
            "toCheckedInvokeCallDerivation",
        ):
            self.assertIn(required, rank_free)
        self.assertNotIn(
            "environmentExact : environment.invokeCall event state = result",
            rank_free,
        )
        self.assertNotIn("CheckedSemanticCallRanking", rank_free)
        self.assertNotIn("ranking.", rank_free)


if __name__ == "__main__":
    unittest.main()
