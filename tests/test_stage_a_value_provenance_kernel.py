from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


class ValueProvenanceKernelTests(unittest.TestCase):
    def test_migrated_indirect_paths_have_one_product_graph_authority(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
            / "RelationalComposition.lean"
        ).read_text(encoding="utf-8")
        body = source[
            source.index("def NodeControlEdgesComplete") :
            source.index("def strictlyIncreasingNatsAux")
        ]
        self.assertIn("NodeIndirectExitEdgesComplete", body)
        self.assertNotIn("NodeImportRegisterIndirectCallEdgesComplete", body)
        self.assertNotIn(
            "NodeFixedCodePointerRegisterIndirectCallEdgesComplete", body
        )
        self.assertNotIn("NodeDynamicRangeIndirectCallEdgesComplete", body)
        self.assertNotIn("NodeImmutableIndirectCallEdgesComplete", body)
        self.assertNotIn(
            "NodeBoundedImmutableCodePointerTableCallEdgesComplete", body
        )
        self.assertNotIn("NodeImmutableIndirectJumpEdgesComplete", body)
        self.assertNotIn("NodeFixedCodeAddressIndirectJumpEdgesComplete", body)
        self.assertNotIn(
            "NodeBoundedImmutableRelocationTableJumpEdgesComplete", body
        )

    def test_unified_provenance_effect_call_and_indirect_interfaces_compile(self):
        source_root = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary) / "lean"
            stage_a = lean_dir / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalIndirectExitAdapters"
            )
            _copy_module_closure(source_root, stage_a, "RelationalCallRefinement")
            (stage_a / "ValueProvenanceInterfaces.lean").write_text(
                """import StageA.RelationalIndirectExitAdapters
import StageA.RelationalCallRefinement

open StageA.Relational
open StageA.Relational.ValueProvenance

#check PairedValueClaim
#check TransitionEffects.RuntimeMemoryImplements
#check TransitionEffects.RuntimeRegistersImplement
#check TransitionEffects.RuntimeRegistersImplement.originalPreserved
#check RegisterValueOriginRelation.holds_of_preserved
#check RegisterValueOriginRelation.holds_of_valueClaim
#check MemoryValueOriginRelation.holds_afterExactWrite
#check MemoryValueOriginRelation.holds_of_read32_eq
#check ValueOriginsPreserved
#check valueOriginsPreserved_sameWorld
#check MemoryValueOriginRelation.holds_of_rebased_read32_eq
#check MemoryValueOriginRelation.holds_afterExactWrite_of_registerOrigin
#check RegisterValueOriginRelation.holds_of_memoryLoad
#check StateInvariant.withAdditionalRegisterValueOriginRelations
#check StateInvariant.withAdditionalMemoryValueOriginRelations
#check StateRel.withAdditionalRegisterValueOriginRelations
#check StateRel.withAdditionalMemoryValueOriginRelations
#check StateRel.afterPreparedWordFrame
#check StateRel.afterPairedPreparedWordUpdatesEvaluation
#check CheckedIndirectExitCertificate
#check NodeIndirectExitEdgesComplete
#check CallRefinement.Refines
#check CallRefinement.Refines.preservedRegisterOrigin
#check CallRefinement.Refines.resultRegisterOrigin
#check CallRefinement.Refines.rebasedMemoryOrigin
#check CallRefinement.Refines.restoredRegisterOrigin
#check IndirectExitAdapters.checkedImmutableCallIndirectCertificate
#check IndirectExitAdapters.checkedStaticWordSlotIndirectCertificate
#check IndirectExitAdapters.checkedStaticWordSlotJumpIndirectCertificate
#check IndirectExitAdapters.checkedImmutableJumpIndirectCertificate
#check IndirectExitAdapters.checkedFixedAddressJumpIndirectCertificate
#check IndirectExitAdapters.checkedBoundedTableCallIndirectCertificate
#check IndirectExitAdapters.checkedBoundedTableJumpIndirectCertificate
#check IndirectExitAdapters.checkedFixedRegisterIndirectCertificate
#check IndirectExitAdapters.checkedImportRegisterIndirectCertificate
#check IndirectExitAdapters.checkedImportRegisterIndirectCertificate_of_closed
#check IndirectExitAdapters.checkedStackFixedIndirectCertificate
#check IndirectExitAdapters.checkedDynamicRangeIndirectCertificate

def opaquePair : OpaqueResourcePair := {
  id := 41
  original := BitVec.ofNat 32 0x70000010
  candidate := BitVec.ofNat 32 0x71000020
}

def opaqueWorld : RelationalWorld := {
  opaqueResources := [opaquePair]
}

def opaqueJumpCertificate : IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := .inputReg .eax
    candidate := .inputReg .eax
    source := .register .eax .eax
    origin := { alternatives := [.opaqueResource 41] }
  }
  destinations := [.opaqueResource 41]
  transfer := .jump
}

example : mappedValueRelated [opaquePair.valueTarget]
    opaquePair.original opaquePair.candidate = true := by decide

example (context : StaticProofContext) :
    ValueOriginAtom.Holds context opaqueWorld opaquePair.original
      opaquePair.candidate (.opaqueResource 41) := by
  exact ⟨opaquePair, by simp [opaqueWorld], rfl, rfl, rfl⟩

example (context : StaticProofContext) :
    opaqueJumpCertificate.checked context = true := by
  simp [opaqueJumpCertificate, IndirectExitCertificate.checked,
    IndirectExitCertificate.destinationShapeChecked,
    PairedValueClaim.checked, ValueSource.checked, ValueOrigin.checked,
    ValueOriginAtom.checked, ValueOrigin.destinations?,
    ValueOriginAtom.destination?]
  all_goals decide

-- Opaque tails have no fabricated static successor: execution must consume a
-- checked callable capability and the top runtime frame in node refinement.
example (context : StaticProofContext) :
    indirectExitExpectedEdges? false context opaqueJumpCertificate = some [] := by
  rfl
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="ValueProvenanceInterfaces"
            )

        self.assertEqual(result["status"], "checked", result)


if __name__ == "__main__":
    unittest.main()
