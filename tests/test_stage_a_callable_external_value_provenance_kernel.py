from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_callable_external_capability_kernel import (
    _copy_module_closure,
)


_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageACallableExternalValueProvenanceKernelTests(unittest.TestCase):
    def test_resolver_result_uses_common_value_provenance(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (
            source_root / "RelationalCallableExternalValueProvenance.lean"
        ).read_text(encoding="utf-8")
        for marker in ("native_decide", "sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalValueProvenance"
            )
            (stage_a / "CallableExternalValueProvenanceKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalValueProvenanceKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertEqual(len(reports), 8, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_SOURCE = r"""import StageA.RelationalCallableExternalValueProvenance

open StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalValueProvenance

#print axioms ExactlyOneFreshCallableResourceIssued.valueOriginsPreserved
#print axioms resolverResultValueClaim_checked
#print axioms ResolverCapabilityResultRelated.resultOriginHolds
#print axioms ResolverCapabilityResultRelated.resultValueClaimHolds
#print axioms ResolverCapabilityResultRelated.resultRegisterOriginHolds
#print axioms ResolverCapabilityResultRelated.targetStateWithResultOrigin
#print axioms ResolverCapabilityResultRelated.resultFiniteRelationHolds
#check ResolverCapabilityResultRelated.staticWordUpdate
#print axioms ResolverCapabilityResultRelated.afterStaticWordUpdate
"""
