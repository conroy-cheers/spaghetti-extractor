from tests.stage_a_relational_support import *


class StageARelationalLeanTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for call-boundary proofs")
    def test_machine_import_call_arguments_are_recovered_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for name in ("Formal.lean", "RelationalDecode.lean"):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "MachineCallBoundary.lean").write_text(
                """import StageA.RelationalDecode

namespace StageA.MachineCallBoundary

open StageA.Formal StageA.Relational

def imported : PEImport := {
  dll := [75, 69, 82, 78, 69, 76, 51, 50, 46, 100, 108, 108]
  name := .symbol [69, 110, 116, 101, 114, 67, 114, 105, 116, 105, 99,
    97, 108, 83, 101, 99, 116, 105, 111, 110]
  iatRva := 4096
}

def contract : MachineImportCallContract := {
  id := 1
  imported := normalizeImport imported
  stackArgumentOffsets := [0]
  stackResultDelta := 4
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  memoryEffect := .argumentRanges
  memoryFootprints := [{
    access := .write
    baseArgument := 0
    offset := 0
    size := .fixed 24
  }]
  worldEffect := .opaqueResources
}

def behavior : SymbolicBehavior := {
  initialSymbolic with
  writes := [(.inputReg .esp, .constant 4259940)]
  outcome := some (.externalCall imported [] 8192)
}

def indirectBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := initialSymbolic.registers.set .esp
    ((Expr.inputReg .esp).offset (2^32 - 4))
  writes := [
    (Expr.inputReg .esp, Expr.constant 7),
    ((Expr.inputReg .esp).offset (2^32 - 4), Expr.constant 4202496)
  ]
  outcome := some (.indirectCall (.inputReg .ebp) 8192 4202496)
}

def preadjustedIndirectBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := initialSymbolic.registers.set .esp
    ((Expr.inputReg .esp).offset (2^32 - 8))
  writes := [
    ((Expr.inputReg .esp).offset (2^32 - 8), Expr.constant 4202500)
  ]
  outcome := some (.indirectCall (.inputReg .ebp) 8196 4202500)
}

def recoveredArgumentChecked : Bool :=
  match applyMachineImportCallContracts [contract] behavior with
  | some recovered =>
      match recovered.outcome with
      | some (.externalCall recoveredImport arguments continuation) =>
          normalizeImport recoveredImport == contract.imported &&
            arguments == contract.arguments behavior && continuation == 8192
      | _ => false
  | none => false

def recoveredArgumentIsDirectWord : Bool :=
  match applyMachineImportCallContracts [contract] behavior with
  | some { outcome := some (.externalCall _ arguments _), .. } =>
      arguments == [.constant 4259940]
  | _ => false

def indirectCallExternalized : Bool :=
  match externalizeRegisterImportCall contract .ebp indirectBehavior with
  | some externalized =>
      externalized.registers.esp == .inputReg .esp &&
        externalized.writes == [(Expr.inputReg .esp, Expr.constant 7)] &&
        externalized.outcome == some (.externalCall contract.imported.syntheticImport
          [.constant 7] 8192)
  | none => false

example : contract.shapeValid = true := by decide
example : recoveredArgumentChecked = true := by decide
example : recoveredArgumentIsDirectWord = true := by decide
example : applyMachineImportCallContracts [contract, contract] behavior = none := by decide
example : indirectCallExternalized = true := by decide
example : externalizeRegisterImportCall contract .edi indirectBehavior = none := by decide
example :
    (externalizeRegisterImportCall { contract with stackArgumentOffsets := [] }
      .ebp preadjustedIndirectBehavior).map (fun behavior => behavior.registers.esp) =
      some ((Expr.inputReg .esp).offset (2^32 - 4)) := by decide

end StageA.MachineCallBoundary
""",
                encoding="utf-8",
            )
            decode = _run_lean_relational(
                lean_dir, bundle="RelationalDecode"
            )
            self.assertEqual(decode["status"], "checked", decode)
            result = _run_lean_relational(
                lean_dir, bundle="MachineCallBoundary"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for dynamic-call proofs")
    def test_dynamic_range_indirect_call_witness_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "DynamicCallWitness.lean").write_text(
                """import StageA.RelationalComposition

namespace StageA.DynamicCallWitness

open StageA.Formal StageA.Relational

def rangeRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  originalOffset := 8
  candidateOffset := 8
  requiredWords := [{ offset := 12, kind := .codePointer }]
}

def rangePair : DynamicAddressRangePair := {
  id := 1
  originalBase := BitVec.ofNat 32 4096
  candidateBase := BitVec.ofNat 32 8192
  size := 32
  wordRelations := rangeRelation.requiredWords
}

def overlappingRangePair : DynamicAddressRangePair := {
  id := 2
  originalBase := BitVec.ofNat 32 4112
  candidateBase := BitVec.ofNat 32 12288
  size := 32
}

def duplicateWordRangePair : DynamicAddressRangePair := {
  rangePair with
  wordRelations := [
    { offset := 12, kind := .codePointer },
    { offset := 12, kind := .dataPointer }
  ]
}

def opaqueWorld : RelationalWorld := {
  opaqueResources := [{
    id := 1
    original := BitVec.ofNat 32 4096
    candidate := BitVec.ofNat 32 8192
  }]
}

def duplicateOpaqueWorld : RelationalWorld := {
  opaqueResources := [
    { id := 1, original := BitVec.ofNat 32 4096,
      candidate := BitVec.ofNat 32 8192 },
    { id := 2, original := BitVec.ofNat 32 4096,
      candidate := BitVec.ofNat 32 12288 }
  ]
}

example : rangePair.wordRelationsValid = true := by decide

example : duplicateWordRangePair.wordRelationsValid = false := by decide

example : opaqueWorld.opaqueResourcesValid = true := by decide

example : duplicateOpaqueWorld.opaqueResourcesValid = false := by decide

example : dynamicAddressRangesDisjointOn false
    [rangePair, overlappingRangePair] = false := by decide

def invariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [rangeRelation]
}

def registers : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def originalBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall
    (.read32 (.add (.inputReg .ebx) (.constant 4))) 9
}

def candidateBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall
    (.read32 (.add (.inputReg .esi) (.constant 4))) 9
}

def claim : DynamicRangeIndirectCallClaim := {
  rangeRelation
  wordOffset := 4
  continuationTargetId := 9
}

def preserveClaim : DynamicRegisterRangePreserveClaim := {
  sourceRelation := rangeRelation
  targetRelation := rangeRelation
}

example : claim.checked invariant originalBehavior candidateBehavior = true := by
  decide

example : DynamicRangeIndirectCallTargetsClosed invariant originalBehavior
    candidateBehavior claim :=
  dynamicRangeIndirectCallTargetsClosed_of_checked invariant originalBehavior
    candidateBehavior claim (by decide)

example : preserveClaim.checked invariant invariant originalBehavior
    originalBehavior = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    preserveClaim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (originalBehavior.eval candidateState).registers = true :=
  dynamicRegisterRangePreserveOutputHolds_of_checked context world invariant invariant
    originalBehavior originalBehavior preserveClaim (by decide) originalState
    candidateState related

def argumentRangeRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  originalOffset := 8
  candidateOffset := 8
  requiredWords := [{ offset := 12, kind := .relatedWord }]
}

def argumentInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [argumentRangeRelation]
}

def argumentClaim : DynamicRangeArgumentClaim := {
  rangeRelation := argumentRangeRelation
  wordRelation := { offset := 12, kind := .relatedWord }
  originalReadOffset := 4
  candidateReadOffset := 4
}

example : argumentClaim.checked argumentInvariant
    (dynamicRangeArgumentExpression .ebx 4)
    (dynamicRangeArgumentExpression .esi 4) = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world argumentInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((dynamicRangeArgumentExpression .ebx 4).eval originalState)
      ((dynamicRangeArgumentExpression .esi 4).eval candidateState) = true :=
  dynamicRangeArgumentWordsRelated_of_checked context world argumentInvariant
    (dynamicRangeArgumentExpression .ebx 4)
    (dynamicRangeArgumentExpression .esi 4) argumentClaim (by decide)
    originalState candidateState related

def exactRegisterArgumentInvariant : StateInvariant := {
  registerRelations := [{ original := .ebx, candidate := .esi, relation := .exact }]
}

def exactRegisterArgumentClaim : RegisterArgumentClaim := {
  relation := { original := .ebx, candidate := .esi, relation := .exact }
  offset := 32
}

example : exactRegisterArgumentClaim.checked exactRegisterArgumentInvariant
    (registerArgumentExpression .ebx 32)
    (registerArgumentExpression .esi 32) = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world exactRegisterArgumentInvariant
      originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((registerArgumentExpression .ebx 32).eval originalState)
      ((registerArgumentExpression .esi 32).eval candidateState) = true :=
  registerArgumentWordsRelated_of_checked context world exactRegisterArgumentInvariant
    (registerArgumentExpression .ebx 32) (registerArgumentExpression .esi 32)
    exactRegisterArgumentClaim (by decide) originalState candidateState related

def relatedRegisterArgumentInvariant : StateInvariant := {
  registerRelations := [
    { original := .ebx, candidate := .esi, relation := .relatedWord }
  ]
}

def relatedRegisterArgumentClaim : RegisterArgumentClaim := {
  relation := { original := .ebx, candidate := .esi, relation := .relatedWord }
  offset := 0
}

example : relatedRegisterArgumentClaim.checked relatedRegisterArgumentInvariant
    (registerArgumentExpression .ebx 0)
    (registerArgumentExpression .esi 0) = true := by decide

example : ({ relatedRegisterArgumentClaim with offset := 4 }).checked
    relatedRegisterArgumentInvariant (registerArgumentExpression .ebx 4)
    (registerArgumentExpression .esi 4) = false := by decide

def nextRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  requiredWords := [
    { offset := 4, kind := .codePointer },
    { offset := 8, kind := .nullableDynamicPointer }
  ]
}

def nextInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [nextRelation]
}

def originalNextRegisters : Registers Expr := {
  registers with
  ebx := dynamicPointerReadExpression .ebx 8
}

def candidateNextRegisters : Registers Expr := {
  registers with
  esi := dynamicPointerReadExpression .esi 8
}

def originalNextBehavior : NormalizedSymbolicBehavior := {
  registers := originalNextRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def candidateNextBehavior : NormalizedSymbolicBehavior := {
  registers := candidateNextRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def originalNextGuard : BoolExpr := dynamicPointerNonzeroGuard .ebx 8
def candidateNextGuard : BoolExpr := dynamicPointerNonzeroGuard .esi 8

def nextClaim : DynamicRegisterRangeNextClaim := {
  sourceRelation := nextRelation
  targetRelation := nextRelation
  pointerOffset := 8
}

example : nextClaim.checked nextInvariant nextInvariant originalNextBehavior
    candidateNextBehavior originalNextGuard candidateNextGuard = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world nextInvariant originalState candidateState)
    (guardTrue : originalNextGuard.eval originalState = true) :
    nextClaim.targetRelation.holds world
      (originalNextBehavior.eval originalState).registers
      (candidateNextBehavior.eval candidateState).registers = true :=
  dynamicRegisterRangeNextOutputHolds_of_checked context world nextInvariant
    nextInvariant originalNextBehavior candidateNextBehavior originalNextGuard
    candidateNextGuard nextClaim (by decide) originalState candidateState related
    guardTrue

def staticSlot : StaticDynamicPointerSlotPair := {
  id := 7
  originalAddress := BitVec.ofNat 32 12288
  candidateAddress := BitVec.ofNat 32 16384
  requiredWords := nextRelation.requiredWords
}

def staticContext (context : StaticProofContext) : StaticProofContext := {
  context with staticDynamicPointerSlots := [staticSlot]
}

def staticOriginalRegisters : Registers Expr := {
  registers with
  ebx := staticDynamicPointerReadExpression staticSlot.originalAddress
}

def staticCandidateRegisters : Registers Expr := {
  registers with
  esi := staticDynamicPointerReadExpression staticSlot.candidateAddress
}

def staticOriginalBehavior : NormalizedSymbolicBehavior := {
  registers := staticOriginalRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def staticCandidateBehavior : NormalizedSymbolicBehavior := {
  registers := staticCandidateRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def staticInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [nextRelation]
}

def staticOriginalGuard : BoolExpr :=
  staticDynamicPointerNonzeroGuard staticSlot.originalAddress

def staticCandidateGuard : BoolExpr :=
  staticDynamicPointerNonzeroGuard staticSlot.candidateAddress

def staticSeedClaim : StaticDynamicPointerSeedClaim := {
  slot := staticSlot
  targetRelation := nextRelation
}

def staticZeroGuardClaim : StaticDynamicPointerGuardClaim := {
  slot := staticSlot
  kind := .zero
}

example (context : StaticProofContext) :
    staticSeedClaim.checked (staticContext context) staticInvariant
      staticOriginalBehavior staticCandidateBehavior staticOriginalGuard
      staticCandidateGuard = true := by rfl

example (context : StaticProofContext) :
    staticZeroGuardClaim.checked (staticContext context)
      (staticDynamicPointerZeroGuard staticSlot.originalAddress)
      (staticDynamicPointerZeroGuard staticSlot.candidateAddress) = true := by rfl

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel (staticContext context) world nextInvariant
      originalState candidateState)
    (guardTrue : staticOriginalGuard.eval originalState = true) :
    staticSeedClaim.targetRelation.holds world
      (staticOriginalBehavior.eval originalState).registers
      (staticCandidateBehavior.eval candidateState).registers = true :=
  staticDynamicPointerSeedOutputHolds_of_checked (staticContext context) world
    nextInvariant staticInvariant staticOriginalBehavior staticCandidateBehavior
    staticOriginalGuard staticCandidateGuard staticSeedClaim (by rfl)
    originalState candidateState related guardTrue

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel (staticContext context) world nextInvariant
      originalState candidateState) :
    (staticDynamicPointerZeroGuard staticSlot.originalAddress).eval originalState =
      (staticDynamicPointerZeroGuard staticSlot.candidateAddress).eval candidateState :=
  staticDynamicPointerGuardsAgree_of_checked (staticContext context) world
    nextInvariant (staticDynamicPointerZeroGuard staticSlot.originalAddress)
    (staticDynamicPointerZeroGuard staticSlot.candidateAddress) staticZeroGuardClaim
    (by rfl) originalState candidateState related

end StageA.DynamicCallWitness
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="DynamicCallWitness"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-call proofs")
    def test_import_register_indirect_call_witness_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "ImportCallWitness.lean").write_text(
                """import StageA.RelationalEnvironment

namespace StageA.ImportCallWitness

open StageA.Formal StageA.Relational

def callerBufferFootprint : MachineCallMemoryFootprint := {
  access := .write
  baseArgument := 0
  offset := 4
  size := .fixed 8
}

def callerBufferContract : MachineImportCallContract := {
  id := 0
  imported := {
    dll := [102, 105, 120, 116, 117, 114, 101, 46, 100, 108, 108]
    name := .symbol [102, 105, 108, 108]
  }
  stackArgumentOffsets := [0]
  stackResultDelta := 4
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  memoryEffect := .argumentRanges
  memoryFootprints := [callerBufferFootprint]
  worldEffect := .none
}

def optionalCallerBufferFootprint : MachineCallMemoryFootprint := {
  callerBufferFootprint with nullable := true
}

def optionalCallerBufferContract : MachineImportCallContract := {
  callerBufferContract with memoryFootprints := [optionalCallerBufferFootprint]
}

def stackArgumentWindow : StackWindowPair := {
  rangeId := 0
  originalRegister := .esp
  candidateRegister := .esp
  bytesBelow := 0
  bytesAbove := 16
}

def stackArgumentInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [stackArgumentWindow]
}

def directStackArgument : Expr :=
  .read32 ((Expr.inputReg .esp).offset 4)

def assembledStackArgument : Expr :=
  stackWindowAssembledArgument .esp 4

def decodedAssembledStackArgument : Expr :=
  .bitOr
    (.bitOr (.read8 ((Expr.inputReg .esp).offset 4))
      (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 5)) 8))
    (.bitOr (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 6)) 16)
      (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 7)) 24))

def stackArgumentClaim : StackWindowArgumentClaim := {
  window := stackArgumentWindow
  offset := 4
  originalAssembledRead := false
  candidateAssembledRead := true
}

example : callerBufferContract.shapeValid = true := by decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 4096] = some (4100, 4108) := by
  decide
example : callerBufferFootprint.contains [BitVec.ofNat 32 4096]
    (BitVec.ofNat 32 4104) = true := by decide
example : callerBufferFootprint.contains [BitVec.ofNat 32 4096]
    (BitVec.ofNat 32 4108) = false := by decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 (2^32 - 8)] = none := by
  decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 0] = none := by decide
example : optionalCallerBufferContract.shapeValid = true := by decide
example : optionalCallerBufferFootprint.range? [BitVec.ofNat 32 0] = some (0, 0) := by
  decide
example : optionalCallerBufferFootprint.contains [BitVec.ofNat 32 0]
    (BitVec.ofNat 32 0) = false := by decide
example : stackArgumentClaim.checked stackArgumentInvariant directStackArgument
    assembledStackArgument = true := by decide
example : assembledStackArgument = decodedAssembledStackArgument := by decide
example (before after : Memory)
    (holds : machineCallMemoryEffectHolds callerBufferContract
      [BitVec.ofNat 32 4096] before after) :
    after (BitVec.ofNat 32 4108) = before (BitVec.ofNat 32 4108) := by
  exact holds.2 _ (by decide)
example (before after : Memory)
    (holds : machineCallMemoryEffectHolds optionalCallerBufferContract
      [BitVec.ofNat 32 0] before after) (address : Word) :
    after address = before address := by
  apply holds.2
  have emptyRange : optionalCallerBufferFootprint.range? [BitVec.ofNat 32 0] =
      some (0, 0) := by decide
  have outside : optionalCallerBufferFootprint.contains [BitVec.ofNat 32 0]
      address = false := by
    simp [MachineCallMemoryFootprint.contains, emptyRange]
  simpa [optionalCallerBufferContract, optionalCallerBufferFootprint,
    callerBufferFootprint] using outside

example : normalizeDllName [75, 69, 82, 78, 69, 76, 51, 50, 46, 100, 108, 108] =
    [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108] := by decide

def imported : ExternalTarget := {
  dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
  name := .symbol [84, 108, 115, 71, 101, 116, 86, 97, 108, 117, 101]
}

def fixtureImport : PEImport := {
  dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
  name := .symbol [84, 108, 115, 71, 101, 116, 86, 97, 108, 117, 101]
  iatRva := 8192
}

example (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (original excludedValues : Memory) :
    ordinaryMemoryRelated context world targets [] original
      (ordinaryMemoryCandidateProjection context world [] original excludedValues) :=
  ordinaryMemoryRelated_projection_without_relocations context world targets []
    original excludedValues (by rfl)

example (context : StaticProofContext) (world : RelationalWorld)
    (original excludedValues : Memory) (address : Word)
    (excluded : ordinaryMemoryAddressExcluded context world [] address = true) :
    ordinaryMemoryCandidateProjection context world [] original excludedValues address =
      excludedValues address := by
  simp [ordinaryMemoryCandidateProjection, excluded]

example (context : StaticProofContext)
    (originalImports : context.originalImports = [fixtureImport]) :
    RelationalWorld.empty.importAddressesComplete context = false := by
  simp [RelationalWorld.importAddressesComplete, RelationalWorld.empty,
    originalImports]

def registers : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def originalBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall (.inputReg .ebp) 7
}

def candidateBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall (.inputReg .edi) 7
}

def invariant : StateInvariant := {
  registerRelations := [{
    original := .ebp
    candidate := .edi
    relation := .relatedWord
  }]
  importRegisterRelations := [{
    original := .ebp
    candidate := .edi
    imported
  }]
}

def claim : ImportRegisterIndirectCallClaim := {
  imported
  originalRegister := .ebp
  candidateRegister := .edi
  continuationTargetId := 7
}

def preserveClaim : ImportRegisterPreserveClaim := {
  imported
  sourceOriginalRegister := .ebp
  sourceCandidateRegister := .edi
  targetOriginalRegister := .ebp
  targetCandidateRegister := .edi
}

    def zeroGuardClaim : RelatedWordZeroGuardClaim := {
      originalRegister := .ebp
      candidateRegister := .edi
      valueRelation := .relatedWord
      notCount := 0
    }

    def sourceStackWindow : StackWindowPair := {
      rangeId := 0
      originalRegister := .esp
      candidateRegister := .esp
      bytesBelow := 4
      bytesAbove := 44
    }

    def targetStackWindow : StackWindowPair := {
      rangeId := 0
      originalRegister := .esp
      candidateRegister := .esp
      bytesBelow := 0
      bytesAbove := 48
    }

    def sourceStackInvariant : StateInvariant := {
      registerRelations := []
      stackWindows := [sourceStackWindow]
    }

    def targetStackInvariant : StateInvariant := {
      registerRelations := []
      stackWindows := [targetStackWindow]
    }

    def adjustedRegisters : Registers Expr := {
      registers with
      esp := .sub (.inputReg .esp) (.constant 4)
    }

    def adjustedBehavior : NormalizedSymbolicBehavior := {
      originalBehavior with registers := adjustedRegisters
    }

    def stackAdjustmentClaim : StackWindowAffineTransferClaim := {
      source := sourceStackWindow
      target := targetStackWindow
      adjustment := .subtract 4
    }

    example : stackAdjustmentClaim.checked sourceStackInvariant targetStackInvariant
        adjustedBehavior adjustedBehavior = true := by decide

    example (context : StaticProofContext) (world : RelationalWorld)
        (originalState candidateState : MachineState)
        (rangesValid : world.stackRangesValid context = true)
        (sourceRelated : stackWindowsRelated world sourceStackInvariant.stackWindows
          originalState.registers candidateState.registers = true) :
        targetStackWindow.holds world
          (adjustedBehavior.eval originalState).registers
          (adjustedBehavior.eval candidateState).registers = true :=
      stackWindowAffineTransferHolds_of_checked context world sourceStackInvariant
        targetStackInvariant adjustedBehavior adjustedBehavior stackAdjustmentClaim
        originalState candidateState rangesValid sourceRelated (by decide)

    example : claim.checked invariant originalBehavior candidateBehavior = true := by decide

example : ImportRegisterIndirectCallTargetsClosed invariant originalBehavior
    candidateBehavior claim :=
  importRegisterIndirectCallTargetsClosed_of_checked invariant originalBehavior
    candidateBehavior claim (by decide)

example : preserveClaim.checked invariant invariant originalBehavior
    candidateBehavior = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    preserveClaim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true :=
  importRegisterPreserveOutputHolds_of_checked context world invariant invariant
    originalBehavior candidateBehavior preserveClaim (by decide) originalState
    candidateState related

example : zeroGuardClaim.checked invariant
    (relatedWordZeroGuard .ebp false) (relatedWordZeroGuard .edi false) = true := by
  decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    (relatedWordZeroGuard .ebp false).eval originalState =
      (relatedWordZeroGuard .edi false).eval candidateState :=
  relatedWordZeroGuard_eval_equal_of_checked context world invariant
    (relatedWordZeroGuard .ebp false) (relatedWordZeroGuard .edi false)
    zeroGuardClaim (by decide) originalState candidateState related

def minusEightWitness : RegisterOffsetWitness :=
  .subRight .input 8

def returnSlotTransferClaim : ReturnSlotTransferClaim := {
  source := ReturnSlotOffsetPair.zero
  target := {
    originalOffset := BitVec.ofNat 32 8
    candidateOffset := BitVec.ofNat 32 8
  }
  originalEsp := minusEightWitness
  candidateEsp := minusEightWitness
}

example : returnSlotTransferClaim.checked adjustedBehavior adjustedBehavior = false := by
  decide

def minusEightRegisters : Registers Expr := {
  registers with
  esp := .sub (.inputReg .esp) (.constant 8)
}

def minusEightBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with registers := minusEightRegisters
}

example : returnSlotTransferClaim.checked minusEightBehavior minusEightBehavior = true := by
  decide

example (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (sourceHolds : ReturnSlotOffsetPair.zero.holds frame originalState.registers
      candidateState.registers) :
    returnSlotTransferClaim.target.holds frame
      (minusEightBehavior.eval originalState).registers
      (minusEightBehavior.eval candidateState).registers :=
  returnSlotTransferHolds_of_checked minusEightBehavior minusEightBehavior
    returnSlotTransferClaim frame originalState candidateState (by decide) sourceHolds

def returnPopClaim : ReturnPopClaim := {
  originalStackAddress := .add (.inputReg .esp) (.constant 8)
  candidateStackAddress := .add (.inputReg .esp) (.constant 8)
  popBytes := 0
}

def returnPopFrameClaim : ReturnPopFrameClaim := {
  offsets := {
    originalOffset := BitVec.ofNat 32 8
    candidateOffset := BitVec.ofNat 32 8
  }
  originalSlot := .addRight .input 8
  candidateSlot := .addRight .input 8
}

example : ReturnPopFrameClaimClosed returnPopClaim returnPopFrameClaim :=
  returnPopFrameClaimClosed_of_checked returnPopClaim returnPopFrameClaim (by decide)

def wrongReturnPopFrameClaim : ReturnPopFrameClaim := {
  returnPopFrameClaim with
  candidateSlot := .addRight .input 12
}

example : wrongReturnPopFrameClaim.checked returnPopClaim = false := by decide

def summaryCallClaim : DirectCallPushClaim := {
  calleeTargetId := 1
  continuationTargetId := 2
  originalReturnAddress := 4096
  candidateReturnAddress := 8192
  originalStackAddress := .sub (.inputReg .esp) (.constant 4)
  candidateStackAddress := .sub (.inputReg .esp) (.constant 4)
}

def summaryReturnRegisters : Registers Expr := {
  registers with
  esp := .add (.inputReg .esp) (.constant 12)
}

def summaryReturnBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := summaryReturnRegisters
  outcome := .returned (.read32 (.add (.inputReg .esp) (.constant 8)))
}

def callSummaryClaim : ReturnSlotCallSummaryClaim := {
  source := ReturnSlotOffsetPair.zero
  target := ReturnSlotOffsetPair.zero
  originalCallEsp := .subRight .input 4
  candidateCallEsp := .subRight .input 4
  originalReturnSlot := .addRight .input 8
  candidateReturnSlot := .addRight .input 8
  originalReturnOutput := .addRight .input 12
  candidateReturnOutput := .addRight .input 12
  popBytes := 0
}

example : ReturnSlotCallSummaryClosed adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim callSummaryClaim :=
  returnSlotCallSummaryClosed_of_checked adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim callSummaryClaim (by decide)

def wrongCallSummaryClaim : ReturnSlotCallSummaryClaim := {
  callSummaryClaim with popBytes := 4
}

example : wrongCallSummaryClaim.checked adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim = false := by decide

def returnAfterWriteSeparations : List AddressSeparationPair :=
  (List.range 4).flatMap fun wordByte =>
    (List.range 4).map fun writeByte => {
      originalRegister := .esp
      candidateRegister := .esp
      originalOffset := wordByte
      candidateOffset := wordByte
      originalAddress := 4198400 + writeByte
      candidateAddress := 5246976 + writeByte
    }

def returnAfterWriteInvariant : StateInvariant := {
  registerRelations := []
  addressSeparations := returnAfterWriteSeparations
}

def originalStaticWrite : Expr × Expr :=
  (.constant 4198400, .read32 (.add (.inputReg .esp) (.constant 4)))

def candidateStaticWrite : Expr × Expr :=
  (.constant 5246976, .read32 (.add (.inputReg .esp) (.constant 4)))

def returnAfterWriteRegisters : Registers Expr := {
  registers with esp := .add (.inputReg .esp) (.constant 4)
}

def originalReturnAfterWriteBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := returnAfterWriteRegisters
  writes := [originalStaticWrite]
  outcome := .returned ((Expr.inputReg .esp).read32AfterWrites [originalStaticWrite])
}

def candidateReturnAfterWriteBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := returnAfterWriteRegisters
  writes := [candidateStaticWrite]
  outcome := .returned ((Expr.inputReg .esp).read32AfterWrites [candidateStaticWrite])
}

def returnAfterWriteClaim : ReturnPopAfterWritesClaim := {
  originalStack := .input
  candidateStack := .input
  originalOutput := .addRight .input 4
  candidateOutput := .addRight .input 4
  popBytes := 0
}

def returnAfterWriteFrameClaim : ReturnPopFrameClaim := {
  offsets := ReturnSlotOffsetPair.zero
  originalSlot := .input
  candidateSlot := .input
}

example : returnAfterWriteClaim.checked returnAfterWriteInvariant
    originalReturnAfterWriteBehavior candidateReturnAfterWriteBehavior = true := by decide

example : ReturnPopAfterWritesFrameClaimClosed returnAfterWriteClaim
    returnAfterWriteFrameClaim :=
  returnPopAfterWritesFrameClaimClosed_of_checked returnAfterWriteClaim
    returnAfterWriteFrameClaim (by decide)

example (context : StaticProofContext) (world : RelationalWorld)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (related : StateRel context world returnAfterWriteInvariant originalState candidateState)
    (offsetsHold : ReturnSlotOffsetPair.zero.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalReturnAfterWriteBehavior.outcome.eval originalState =
        .returned frame.originalReturnAddress ∧
      candidateReturnAfterWriteBehavior.outcome.eval candidateState =
        .returned frame.candidateReturnAddress :=
  returnPopAfterWritesTargetsRuntimeFrame_of_checked context world
    returnAfterWriteInvariant originalReturnAfterWriteBehavior
    candidateReturnAfterWriteBehavior returnAfterWriteClaim returnAfterWriteFrameClaim
    frame originalState candidateState (by decide) (by decide) related offsetsHold memoryHolds

end StageA.ImportCallWitness
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="ImportCallWitness"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for reachability proofs")
    def test_constant_false_edge_is_excluded_by_checked_reachability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("39c07502ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "constant-branch",
                    "kind": "code",
                    "reachable": True,
                    "root": {"kind": "fixture_function", "checked": True},
                    "original": {"rva": 0x1000, "size": 4},
                    "candidate": {"rva": 0x1000, "size": 4},
                },
                {
                    "id": "fallthrough-loop",
                    "kind": "code",
                    "reachable": True,
                    "original": {"rva": 0x1004, "size": 2},
                    "candidate": {"rva": 0x1004, "size": 2},
                },
                {
                    "id": "infeasible-loop",
                    "kind": "code",
                    "reachable": True,
                    "original": {"rva": 0x1006, "size": 2},
                    "candidate": {"rva": 0x1006, "size": 2},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            self.assertEqual(generated["status"], "generated", generated)

            report = root / "report"
            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(encoding="utf-8")
            )
            infeasible = [edge for edge in graph["edges"] if edge["infeasible"]]
            self.assertEqual(len(infeasible), 1, graph)
            self.assertNotIn(
                infeasible[0]["target_node_id"],
                graph["evidence"]["declared_reachable_node_ids"],
            )
            reachability = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("SoundlyClosed", reachability)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for branch refinement proofs")
    def test_related_word_zero_branch_segments_are_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("85c07402ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            spans = [(0x1000, 4), (0x1004, 2), (0x1006, 2)]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, (rva, _) in enumerate(spans)
                ],
                "regions": [
                    {
                        "id": f"zero-branch-{index}",
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                        "flag_inputs": [10],
                        "flag_outputs": [10],
                    }
                    for index, (rva, size) in enumerate(spans)
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")
            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            graph = json.loads(
                (root / "report" / "relational-product-graph.json").read_text()
            )
            self.assertGreaterEqual(graph["counts"]["proved_edges"], 2, graph)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                )
            )
            self.assertIn("RelatedWordZeroGuardClaim", segment_source)
