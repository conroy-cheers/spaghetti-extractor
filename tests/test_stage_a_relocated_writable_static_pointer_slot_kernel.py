from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.relocated_writable_static_pointer_slot_proposal import (
    LeanAuthorityBinding,
    construct_relocated_writable_static_pointer_slot_authorities,
    write_relocated_writable_static_pointer_slot_authorities,
)
from tests.test_stage_a_reachable_static_pointer_slot_kernel import (
    _authority_source,
    _copy_module_closure,
)
from tests.test_stage_a_nullable_code_pointer_table import TEXT_RVA
from tests.test_stage_a_relocated_writable_static_pointer_slot_proposal import (
    SLOT_RVA,
    SLOT_VA,
    TARGET_RVA,
    _fixture,
)


_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


def _fixture_authority_source(
    pe_path: Path,
    pe_bytes: bytes,
    source_size: int,
    continuation_rva: int,
    *,
    jump: bool = False,
) -> str:
    entries = ", ".join(
        (
            f"{{ id := 0, regionIndex := 0, rva := {TEXT_RVA} }}",
            f"{{ id := 1, regionIndex := 1, rva := {continuation_rva} }}",
            f"{{ id := 2, regionIndex := 2, rva := {TARGET_RVA} }}",
        )
    )
    addresses = ", ".join(
        f"{{ targetId := {index}, kind := .canonical }}"
        for index in range(3)
    )
    regions = ", ".join(
        (
            f"{{ id := 0, span := {{ start := {TEXT_RVA}, size := {source_size} }}, "
            f"root := true, targets := {[2] if jump else [1, 2]} }}",
            f"{{ id := 1, span := {{ start := {continuation_rva}, size := 1 }}, "
            "root := false, targets := [] }",
            f"{{ id := 2, span := {{ start := {TARGET_RVA}, size := 1 }}, "
            "root := false, targets := [] }",
        )
    )
    return _authority_source(
        pe_path,
        pe_bytes,
        source_size,
        entries=entries,
        addresses=addresses,
        regions=regions,
        check_size=3,
    ) + f"""

namespace StageA.GeneratedReachableSlotFixture

open StageA.Formal StageA.Relational

def carrierCodeMap : StaticCodeMap := {{
  entries := .leaf [
    {{ id := 0, regionIndex := 0, originalRva := {TEXT_RVA},
      candidateRva := {TEXT_RVA} }},
    {{ id := 1, regionIndex := 1, originalRva := {continuation_rva},
      candidateRva := {continuation_rva} }},
    {{ id := 2, regionIndex := 2, originalRva := {TARGET_RVA},
      candidateRva := {TARGET_RVA} }}
  ]
  originalAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }},
    {{ targetId := 2, kind := .canonical }}
  ]
  candidateAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }},
    {{ targetId := 2, kind := .canonical }}
  ]
}}

def carrierSlot : StaticWordRelationSlotPair := {{
  id := {SLOT_RVA}
  originalAddress := BitVec.ofNat 32 {SLOT_VA}
  candidateAddress := BitVec.ofNat 32 {SLOT_VA}
  relation := .fixedCodePointer 2
}}

def carrierContext : StaticProofContext := {{
  originalPe := originalContext.pe
  candidatePe := originalContext.pe
  originalImportCertificate := originalContext.importCertificate
  candidateImportCertificate := originalContext.importCertificate
  originalRelocations := originalContext.relocations
  candidateRelocations := originalContext.relocations
  codeMap := carrierCodeMap
  dataMap := {{ entries := #[], originalOrder := [], candidateOrder := [] }}
  roots := []
  observations := {{}}
  staticWordRelationSlots := [carrierSlot]
  machineImportCallContracts := originalContext.machineImportCallContracts
}}

end StageA.GeneratedReachableSlotFixture
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelocatedWritableStaticPointerSlotKernelTests(unittest.TestCase):
    def test_static_authority_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root / "RelationalRelocatedWritableStaticPointerSlot.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("native_decide", layer)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        for jump in (False, True):
            with self.subTest(transfer="jump" if jump else "call"):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    stage_a = root / "StageA"
                    stage_a.mkdir()
                    _copy_module_closure(
                        source_root,
                        stage_a,
                        "RelationalRelocatedWritableStaticPointerSlot",
                    )
                    pe, state, machine, mixed = _fixture(root, jump=jump)
                    source_size = mixed.regions[0].size
                    continuation_rva = mixed.regions[1].rva
                    (stage_a / "GeneratedReachableSlotFixture.lean").write_text(
                        _fixture_authority_source(
                            pe,
                            pe.read_bytes(),
                            source_size,
                            continuation_rva,
                            jump=jump,
                        ),
                        encoding="utf-8",
                    )
                    proposal = (
                        construct_relocated_writable_static_pointer_slot_authorities(
                            original_pe=pe,
                            state_machine=state,
                            machine_import_report=machine,
                            mixed_original_plan=mixed,
                        )
                    )
                    _, sources = (
                        write_relocated_writable_static_pointer_slot_authorities(
                            root,
                            proposal,
                            LeanAuthorityBinding(
                                dependency_modules=(
                                    "StageA.GeneratedReachableSlotFixture",
                                ),
                                context_term=(
                                    "StageA.GeneratedReachableSlotFixture.originalContext"
                                ),
                                carrier_term=(
                                    "StageA.GeneratedReachableSlotFixture.carrierContext"
                                ),
                                decoded_authority_term=(
                                    "StageA.GeneratedReachableSlotFixture.originalAuthority"
                                ),
                            ),
                        )
                    )
                    generated = sources[0]
                    generated.write_text(
                        generated.read_text(encoding="utf-8").replace(
                            "#print axioms generatedCertificateChecked",
                            """theorem changedSlotRejected :
        let changed := {
          generatedCertificate with
          slotRva := generatedCertificate.slotRva + 4
        }
        changed.instructionMatches
          StageA.GeneratedReachableSlotFixture.originalContext = false := by
      decide +kernel

    theorem wrappedNegativeWriteOffsetCanonical :
        ({ register := .esp, offset := 4294967268, value := .constant 1,
            subtract := true } :
          RegisterOffsetWrite).address =
            .sub (.inputReg .esp) (.constant 28) := by
      decide +kernel

    theorem wrappedAddWriteOffsetPreserved :
        ({ register := .esp, offset := 4294967292, value := .constant 1,
            subtract := false } :
          RegisterOffsetWrite).address =
            .add (.inputReg .esp) (.constant 4294967292) := by
      decide +kernel

    #print axioms generatedCertificateChecked""",
                        ),
                        encoding="utf-8",
                    )
                    bundle = sources[0].stem
                    result = _run_lean_relational(root, bundle=bundle)

                self.assertEqual(result["status"], "checked", result)
                output = result["stdout"] + result["stderr"]
                self.assertNotIn("sorryAx", output)
                self.assertNotIn("native_decide.ax", output)
                for match in _AXIOMS.findall(output):
                    axioms = {
                        item.strip()
                        for item in match.split(",")
                        if item.strip()
                    }
                    self.assertLessEqual(axioms, _APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
