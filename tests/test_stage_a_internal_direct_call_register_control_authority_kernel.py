from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_internal_direct_call_register_summary_kernel import (
    _copy_module_closure,
)


_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}
_FIXTURE = "RelationalInternalDirectCallRegisterControlAuthorityFixture"


class StageAInternalDirectCallRegisterControlAuthorityKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_identity_call_entry_register_is_kernel_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA",
                stage_a,
                "RelationalInternalDirectCallMixedOriginalIntegration",
            )
            (stage_a / f"{_FIXTURE}.lean").write_text(
                """import StageA.RelationalInternalDirectCallMixedOriginalIntegration

namespace StageA.Generated.RegisterControlAuthorityFixture

open StageA.Formal StageA.Relational

theorem evalBehaviorPreservesIdentityRegister
    (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior)
    (result : RelationalBehavior) (register : Reg)
    (identity : behavior.registers.get register = .inputReg register)
    (evaluated : evalBehavior candidate targets state behavior = some result) :
    (result.nextMachineState state).registers.get register =
      state.registers.get register := by
  cases normalizedEquation :
      normalizeSymbolicBehavior candidate targets behavior with
  | none => simp [evalBehavior, normalizedEquation] at evaluated
  | some normalized =>
    have fields := normalizeSymbolicBehavior_fields candidate targets behavior
      normalized normalizedEquation
    simp [evalBehavior, normalizedEquation] at evaluated
    subst result
    simp [NormalizedSymbolicBehavior.eval, fields.1, identity,
      RelationalBehavior.nextMachineState, Expr.eval]

#print axioms evalBehaviorPreservesIdentityRegister

end StageA.Generated.RegisterControlAuthorityFixture
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(root, bundle=_FIXTURE)

            self.assertEqual(result["status"], "checked", result)
            output = result.get("stdout", "") + result.get("stderr", "")
            reports = _AXIOM_REPORT.findall(output)
            self.assertTrue(reports, output)
            used = {
                item.strip()
                for report in reports
                for item in report.split(",")
                if item.strip()
            }
            self.assertLessEqual(used, _APPROVED_AXIOMS, output)


if __name__ == "__main__":
    unittest.main()
