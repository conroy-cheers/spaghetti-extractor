from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IDENTITY_KERNEL_MODULES = (
    "X87",
    "RelationalX87",
    "Formal",
    "RelationalX87Decode",
    "ISAQualification",
    "RelationalDecode",
    "RelationalLoader",
    "RelationalFiniteIndex",
    "RelationalMachine",
    "RelationalPEExecution",
    "RelationalISAQualification",
    "Relational",
    "RelationalX87Machine",
    "RelationalInvariant",
    "RelationalExecution",
    "RelationalImage",
    "RelationalExactExpr",
    "RelationalSegment",
    "RelationalComposition",
    "RelationalLinkedFrames",
    "RelationalEnvironment",
    "RelationalCallbacks",
    "RelationalAffineFrames",
    "RelationalCertificates",
    "RelationalIdentity",
)


class StageARelationalIdentityKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_current_pe32_world_reflexivity_intermediate_is_kernel_checked(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        source = (source_root / "RelationalIdentity.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertNotIn("identityProgramSemantics", source)
        self.assertIn("DecodedWorldProgram", source)
        self.assertIn("pe32TransitionSystem", source)
        self.assertIn("WorldExecution", source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in _IDENTITY_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean", stage_a / f"{module}.lean"
                )
            (stage_a / "RelationalIdentityKernel.lean").write_text(
                """import StageA.RelationalIdentity

namespace StageA.RelationalIdentityKernel

open StageA.Formal StageA.Relational

variable {context : StaticProofContext}
variable {graph : RelationalProductGraph}
variable {invariants : ProductInvariantTable}
variable {reachability : RelationalProductReachabilityEvidence}
variable {control : ProductControlProfile}
variable {launch : PE32ConsoleLaunchV2}
variable {original candidate : DecodedWorldProgram}
variable {originalEnvironment candidateEnvironment : WorldExternalEnvironment}
variable {originalProtocolEnvironment candidateProtocolEnvironment :
  WorldExternalProtocolEnvironment}
variable {originalBytes candidateBytes : ByteTree}
variable {decodedIds reachableIds : List Nat}

example
    (evidence : ExactPE32WorldIdentityEvidence "hash" "hash"
      originalBytes candidateBytes decodedIds reachableIds context original candidate
      originalEnvironment candidateEnvironment originalProtocolEnvironment
      candidateProtocolEnvironment)
    (frontier : ExactIdentityPE32CheckedFrontier context graph original.regions
      reachableIds invariants reachability control launch original candidate) :
    ExactIdentityPE32WorldReflexivityIntermediate "hash" "hash"
      originalBytes candidateBytes decodedIds reachableIds context graph
      original.regions invariants reachability control launch original candidate
      originalEnvironment candidateEnvironment originalProtocolEnvironment
      candidateProtocolEnvironment :=
  evidence.worldReflexivityIntermediate frontier

example (reason : ExecutionBlock) :
    ¬ worldRelationalObservationsRelated context
      (some (.proofBlocked reason)) (some (.proofBlocked reason)) := by
  simp [worldRelationalObservationsRelated]

#print axioms ExactPE32WorldIdentityEvidence.worldReflexivityIntermediate

end StageA.RelationalIdentityKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalIdentityKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
