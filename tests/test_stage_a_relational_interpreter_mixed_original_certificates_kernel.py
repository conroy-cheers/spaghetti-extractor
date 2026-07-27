from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from test_stage_a_relational_interpreter_mixed_original import (
    _pe32_static_indirect_image,
    _spec,
    _static_indirect_rows,
    _write_jsonl,
)
from test_stage_a_relational_interpreter_mixed_original_kernel import (
    _TINY_ORIGINAL,
)

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
    _lean_relocations,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    OriginalPERecoveryInput,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original_base,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_certificates import (
    decompose_interpreter_mixed_original_base,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalInterpreterMixedOriginalCertificateKernelTests(
    unittest.TestCase
):
    def test_decomposed_tiny_exact_authority_compiles(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        image = _pe32_static_indirect_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            pe = root / "original.exe"
            pe.write_bytes(image)
            binary = _parse_stage_a_pe(pe)
            try:
                original_module = _TINY_ORIGINAL.format(
                    byte_tree=_lean_byte_tree_definitions(
                        "originalBytes", image
                    ),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                    relocations_literal=_lean_relocations(binary),
                )
            finally:
                binary.pe.close()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedOriginalCertificates",
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedOriginalReachabilityCertificates",
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterOriginalCarrierBinding",
            )
            (stage_a / "GeneratedTinyOriginalPE.lean").write_text(
                original_module,
                encoding="utf-8",
            )
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            write_relational_interpreter_mixed_original_base(root, plan)
            decompose_interpreter_mixed_original_base(root, plan)
            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalInterpreterMixedOriginalBase",
            )

        self.assertEqual(result["status"], "checked", result)
        output = str(result["stdout"]) + str(result["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide", output)

    def test_proof_oriented_certificate_converts_without_new_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterMixedOriginalCertificates",
            )
            (stage_a / "GeneratedCertificateCompositionAudit.lean").write_text(
                _AUDIT,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedCertificateCompositionAudit"
            )

        self.assertEqual(result["status"], "checked", result)
        output = str(result["stdout"]) + str(result["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 3, output)
        for report in reports:
            used = {
                item.strip() for item in report.split(",") if item.strip()
            }
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)


_AUDIT = r"""
import StageA.RelationalInterpreterMixedOriginalCertificates

namespace StageA.GeneratedRelational.CertificateCompositionAudit

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

def emptyOriginalCodeMap : OriginalCodeMap := {
  entries := .empty
  addresses := .empty
}

def emptyChecks : IndexedBoolCertificate := { ranges := [] }

def emptyProofCertificate (pe : PE32) (imports : List PEImport) :
    OriginalCodeMapProofCertificate pe imports emptyOriginalCodeMap := {
  entriesStructurallyValid := by decide
  addressesStructurallyValid := by decide
  entryChecks := emptyChecks
  entryChecksCoverage := by decide
  entriesValid := by
    intro index before
    simp [emptyOriginalCodeMap, FiniteIndex.size] at before
  addressCountExact := by decide
  addressChecks := emptyChecks
  addressChecksCoverage := by decide
  addressesValid := by
    intro index before
    simp [emptyOriginalCodeMap, FiniteIndex.size] at before
  roundTripChecks := emptyChecks
  roundTripChecksCoverage := by decide
  targetsRoundTrip := by
    intro index before
    simp [emptyOriginalCodeMap, FiniteIndex.size] at before
  aliasChecks := emptyChecks
  aliasChecksCoverage := by decide
  aliasesValid := by
    intro index before
    simp [emptyOriginalCodeMap, FiniteIndex.size] at before
}

example (pe : PE32) (imports : List PEImport) :
    OriginalCodeMapCertificate pe imports emptyOriginalCodeMap :=
  (emptyProofCertificate pe imports).toBooleanCertificate

#print axioms indexedBoolRangesValid_of_coverage_and_holds
#print axioms FiniteIndex.structurallyValid_branch
#print axioms OriginalCodeMapProofCertificate.toBooleanCertificate

end StageA.GeneratedRelational.CertificateCompositionAudit
"""


if __name__ == "__main__":
    unittest.main()
