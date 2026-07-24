from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.opaque_lockstep_environment import (
    relational_opaque_lockstep_acceptance_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageAOpaqueLockstepEnvironmentKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_opaque_lockstep_profile_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (
            source_root / "RelationalOpaqueLockstepEnvironment.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (
                *RELATIONAL_KERNEL_MODULES,
                "RelationalOpaqueLockstepEnvironment",
            ):
                shutil.copyfile(source_root / f"{module}.lean", stage_a / f"{module}.lean")
            (stage_a / "RelationalAcceptanceOpaqueLockstep.lean").write_text(
                relational_opaque_lockstep_acceptance_source(), encoding="utf-8"
            )
            (stage_a / "OpaqueLockstepKernel.lean").write_text(
                """import StageA.RelationalAcceptanceOpaqueLockstep

namespace StageA.OpaqueLockstepKernel
open StageA.Formal StageA.Relational

example (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (checked : CheckedOpaqueLockstepEnvironment context sites original candidate)
    (site : OpaqueLockstepCallSite) (member : site \u2208 sites)
    (returns : site.disposition = .returns) :
    OpaqueLockstepEnvironmentRefinesAt context site original candidate :=
  checked.at context sites original candidate site member returns

example (context : StaticProofContext) (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEvent)
    (related : OpaqueLockstepBoundaryRelated context site original candidate) :
    original.imported = candidate.imported := by
  rw [related.2.2.2.2.1, related.2.2.2.2.2.1]

example (context : StaticProofContext) (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (refines : OpaqueLockstepEnvironmentRefinesAt context site original candidate)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : OpaqueLockstepBoundaryRelated context site
      originalEvent candidateEvent) :
    OpaqueLockstepResultRelated context site originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent) :=
  refines eventIndex originalEvent candidateEvent boundary

#print axioms CheckedOpaqueLockstepEnvironment.at
#print axioms OpaqueLockstepEnvironmentsRefine.at

end StageA.OpaqueLockstepKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(root, bundle="OpaqueLockstepKernel")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
