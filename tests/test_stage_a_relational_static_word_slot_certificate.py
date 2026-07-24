from tests.stage_a_relational_support import *


class StageARelationalStaticWordSlotCertificateTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for certificate proofs")
    def test_indexed_static_word_slot_certificate_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "StaticWordSlotCertificate.lean").write_text(
                """import StageA.RelationalCertificates

namespace StageA.StaticWordSlotCertificate

open StageA.Formal StageA.Relational

def testSlot (relation : StaticWordRelationKind) : StaticWordRelationSlotPair := {
  id := 7
  originalAddress := BitVec.ofNat 32 4096
  candidateAddress := BitVec.ofNat 32 8192
  relation := relation
}

def testContext (context : StaticProofContext)
    (relation : StaticWordRelationKind) : StaticProofContext :=
  { context with staticWordRelationSlots := [testSlot relation] }

example (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory) (relation : StaticWordRelationKind) :
    staticWordRelationSlotMemoryHoldAt (testContext context relation) world
        original candidate 0 =
      (testSlot relation).memoryHolds (testContext context relation) world
        original candidate := by
  rfl

example (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory) (relation : StaticWordRelationKind) :
    staticWordRelationSlotMemoryHoldAt (testContext context relation) world
      original candidate 1 = false := by
  rfl

example (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory) (certificate : IndexedBoolCertificate)
    (checked : certificate.Holds
      (staticWordRelationSlotMemoryHoldAt context world original candidate)
      context.staticWordRelationSlots.length) :
    StaticWordRelationSlotsMemoryHold context world original candidate := by
  exact staticWordRelationSlotsMemoryHold_of_indexed_holds context world
    original candidate certificate checked

example (context : StaticProofContext) (world : RelationalWorld) :
    (StaticWordRelationKind.finiteOrigins 1 [.exactBits 17]).holds
      context world (BitVec.ofNat 32 17) (BitVec.ofNat 32 17) = true := by
  simp [StaticWordRelationKind.holds, ValueOriginAtom.matches]

def resource : OpaqueResourcePair := {
  id := 23
  original := BitVec.ofNat 32 40960
  candidate := BitVec.ofNat 32 45056
}

def resourceWorld : RelationalWorld := {
  opaqueResources := [resource]
}

example (context : StaticProofContext) :
    (StaticWordRelationKind.finiteOrigins 1 [.opaqueResource 23]).holds
      context resourceWorld resource.original resource.candidate = true := by
  simp [StaticWordRelationKind.holds, ValueOriginAtom.matches, resourceWorld,
    resource]

end StageA.StaticWordSlotCertificate
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="StaticWordSlotCertificate"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])
