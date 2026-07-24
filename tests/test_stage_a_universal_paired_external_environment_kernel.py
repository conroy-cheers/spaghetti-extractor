from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageAUniversalPairedExternalEnvironmentKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_universal_response_constructor_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        support = (
            source_root / "RelationalUniversalPairedExternalEnvironment.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", support), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            modules = (
                *RELATIONAL_KERNEL_MODULES,
                "RelationalStaticMachineImportContracts",
                "RelationalUniversalPairedExternalEnvironment",
            )
            for module in dict.fromkeys(modules):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "UniversalPairedExternalEnvironmentKernel.lean").write_text(
                """import StageA.RelationalUniversalPairedExternalEnvironment

namespace StageA.UniversalPairedExternalEnvironmentKernel

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.Relational.UniversalPairedExternalEnvironment

example (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment)
    (returns : contract.disposition = .returns)
    (checked : CheckedUniversalPairedMachineResponse context site contract
      original candidate) :
    ExternalEnvironmentRefinesAt context site contract original candidate :=
  externalEnvironmentRefinesAt_of_universalPairedResponse context site contract
    original candidate returns checked

example
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (certificate : UniversalPairedExternalEnvironmentCertificate pair context
      sites original candidate) :
    ExternalEnvironmentRefines context sites original candidate :=
  certificate.refines pair context sites original candidate

#print axioms externalEnvironmentRefinesAt_of_universalPairedResponse
#print axioms UniversalPairedExternalEnvironmentCertificate.refines

end StageA.UniversalPairedExternalEnvironmentKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="UniversalPairedExternalEnvironmentKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
