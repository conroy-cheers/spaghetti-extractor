import StageA.RelationalOriginalTargetPreservation

namespace StageA.Relational.OriginalMemoryEffectPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

/-!
# Generic one-sided memory-effect preservation

This module turns checked transition footprints into the per-word updates used
by `OriginalStaticWordPostEvidence`.  It does not infer footprints.  A caller
must provide exact concrete or symbolic writes, checked disjointness, an exact
unchanged read, or an explicit related replacement.  x87 stores and external
results use the same interface and remain fail closed when their footprints are
not available.
-/

/-- A variable-width byte write avoids every byte of a protected 32-bit word. -/
def ByteWritesAvoidWord (wordAddress writeAddress : Word) (bytes : Nat) : Prop :=
  forall wordByte, wordByte < 4 -> forall writeByte, writeByte < bytes ->
    wordAddress + BitVec.ofNat 32 wordByte ≠
      writeAddress + BitVec.ofNat 32 writeByte

theorem Memory.read32_write8_of_avoids
    (memory : Memory) (wordAddress writeAddress : Word) (value : BitVec 8)
    (avoids : forall wordByte, wordByte < 4 ->
      wordAddress + BitVec.ofNat 32 wordByte ≠ writeAddress) :
    Memory.read32 (Memory.write8 memory writeAddress value) wordAddress =
      Memory.read32 memory wordAddress := by
  have h0 : wordAddress ≠ writeAddress := by
    simpa using avoids 0 (by omega)
  have h1 : wordAddress + BitVec.ofNat 32 1 ≠ writeAddress :=
    avoids 1 (by omega)
  have h2 : wordAddress + BitVec.ofNat 32 2 ≠ writeAddress :=
    avoids 2 (by omega)
  have h3 : wordAddress + BitVec.ofNat 32 3 ≠ writeAddress :=
    avoids 3 (by omega)
  simp [Memory.read32, Memory.write8, h0, h1, h2, h3]

theorem Memory.read32_writeX87Bits_of_avoids
    (memory : Memory) (wordAddress writeAddress : Word)
    (bits : BitVec 80) (bytes : Nat)
    (avoids : ByteWritesAvoidWord wordAddress writeAddress bytes) :
    Memory.read32 (Memory.writeX87Bits memory writeAddress bits bytes)
        wordAddress =
      Memory.read32 memory wordAddress := by
  induction bytes generalizing memory with
  | zero => rfl
  | succ bytes induction =>
      rw [Memory.writeX87Bits]
      rw [Memory.read32_write8_of_avoids]
      · exact induction memory (fun wordByte wordBefore writeByte writeBefore =>
          avoids wordByte wordBefore writeByte (Nat.lt_succ_of_lt writeBefore))
      · intro wordByte wordBefore
        exact avoids wordByte wordBefore bytes (Nat.lt_succ_self bytes)

/-- The concrete x87 store selected by a checked machine effect avoids a word.
No-store effects satisfy the predicate definitionally. -/
def X87MemoryEffectAvoidsWord (wordAddress : Word)
    (effect : StageA.X87.MachineEffect) : Prop :=
  match effect.response.store, effect.memoryAddress with
  | some store, some address =>
      ByteWritesAvoidWord wordAddress address store.kind.byteWidth
  | _, _ => True

theorem Memory.read32_applyX87MemoryEffect_of_avoids
    (memory : Memory) (wordAddress : Word)
    (effect : StageA.X87.MachineEffect)
    (avoids : X87MemoryEffectAvoidsWord wordAddress effect) :
    Memory.read32 (applyX87MemoryEffect memory effect) wordAddress =
      Memory.read32 memory wordAddress := by
  cases storeExact : effect.response.store with
  | none => simp [applyX87MemoryEffect, storeExact]
  | some store =>
      cases addressExact : effect.memoryAddress with
      | none => simp [applyX87MemoryEffect, storeExact, addressExact]
      | some address =>
          simp only [X87MemoryEffectAvoidsWord, storeExact, addressExact] at avoids
          simp only [applyX87MemoryEffect, storeExact, addressExact]
          exact Memory.read32_writeX87Bits_of_avoids memory wordAddress address
            store.bits store.kind.byteWidth avoids

/-- Executable disjointness for a normalized symbolic write list.  This small
checker is intentionally independent of the native operation-trace modules. -/
def normalizedWritesAvoidWordChecked (wordAddress : Word)
    (state : MachineState) (writes : List (Expr × Expr)) : Bool :=
  (evalNormalizedWrites state writes).all fun write =>
    wordOffsetsDisjoint wordAddress write.1

theorem write32AvoidsWord_of_normalizedDisjoint
    {wordAddress writeAddress : Word}
    (checked : wordOffsetsDisjoint wordAddress writeAddress = true) :
    Write32AvoidsWord wordAddress writeAddress := by
  simp only [wordOffsetsDisjoint, List.all_eq_true] at checked
  intro wordByte wordBefore writeByte writeBefore
  have wordChecked := checked wordByte (by simpa using wordBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeBefore)
  simpa only [decide_eq_true_eq] using writeChecked

theorem normalizedWritesAvoidWord_of_checked (wordAddress : Word)
    (state : MachineState) (writes : List (Expr × Expr))
    (checked : normalizedWritesAvoidWordChecked wordAddress state writes = true) :
    WritesAvoidWord wordAddress (evalNormalizedWrites state writes) := by
  simp only [normalizedWritesAvoidWordChecked, List.all_eq_true] at checked
  intro write member
  exact write32AvoidsWord_of_normalizedDisjoint (checked write member)

/-- Runtime writes are proposed one concrete evaluated address at a time.  The
checked partition and range witness then discharge the existing byte-level
protected-word checker; no storage-class-specific preservation rule is needed. -/
structure OriginalNormalizedRuntimeWritesEvidence
    (world : RelationalWorld) (input : MachineState)
    (writes : List (Expr × Expr)) where
  access : forall write, write ∈ evalNormalizedWrites input writes ->
    OriginalRuntimeAccessWitness world write.1 4

theorem normalizedWritesAvoidWordChecked_of_runtimePartition
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world) (input : MachineState)
    (writes : List (Expr × Expr))
    (runtime : OriginalNormalizedRuntimeWritesEvidence world input writes)
    (wordAddress : Word)
    (wordValid : writableStaticWordInPe context.originalPe wordAddress = true) :
    normalizedWritesAvoidWordChecked wordAddress input writes = true := by
  simp only [normalizedWritesAvoidWordChecked, List.all_eq_true]
  intro write member
  simp only [wordOffsetsDisjoint, List.all_eq_true, decide_eq_true_eq]
  intro wordByte wordByteMember writeByte writeByteMember
  exact (runtime.access write member).avoidsWritableStaticWord partition wordValid
    wordByte (List.mem_range.mp wordByteMember)
    writeByte (List.mem_range.mp writeByteMember)

theorem normalizedWritesAvoidWordChecked_singleton
    (wordAddress : Word) (state : MachineState)
    (address value : Expr) (concreteAddress : Word)
    (addressExact : address.eval state = concreteAddress)
    (disjoint : wordOffsetsDisjoint wordAddress concreteAddress = true) :
    normalizedWritesAvoidWordChecked wordAddress state [(address, value)] = true := by
  simp [normalizedWritesAvoidWordChecked, evalNormalizedWrites, addressExact,
    disjoint]

/-- Checked evidence for the memory side of one normalized internal effect.
The constructors are intentionally exhaustive only over supplied proof
objects; there is no fallback for an unknown write. -/
inductive OriginalWordEffectEvidence
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement) : Prop where
  | concreteWrites (writes : List (Word × Word))
      (afterMemoryExact : afterMemory = applyConcreteWrites beforeMemory writes)
      (avoids : WritesAvoidWord requirement.slot.originalAddress writes)
      (originsPreserved : requirement.OriginsPreserved context beforeWorld
        afterWorld) :
      OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | symbolicWrites (input : MachineState)
      (behavior : NormalizedSymbolicBehavior)
      (beforeMemoryExact : input.memory = beforeMemory)
      (afterMemoryExact : afterMemory =
        ((behavior.eval input).nextMachineState input).memory)
      (avoids : normalizedWritesAvoidWordChecked
        requirement.slot.originalAddress input behavior.writes = true)
      (originsPreserved : requirement.OriginsPreserved context beforeWorld
        afterWorld) :
      OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | x87Writes (writes : List (Word × Word))
      (effect : StageA.X87.MachineEffect)
      (afterMemoryExact : afterMemory = applyX87MemoryEffect
        (applyConcreteWrites beforeMemory writes) effect)
      (writesAvoid : WritesAvoidWord requirement.slot.originalAddress writes)
      (x87Avoid : X87MemoryEffectAvoidsWord
        requirement.slot.originalAddress effect)
      (originsPreserved : requirement.OriginsPreserved context beforeWorld
        afterWorld) :
      OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | unchangedRead
      (readExact : Memory.read32 afterMemory requirement.slot.originalAddress =
        Memory.read32 beforeMemory requirement.slot.originalAddress)
      (originsPreserved : requirement.OriginsPreserved context beforeWorld
        afterWorld) :
      OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | relatedUpdate
      (afterHolds : requirement.Holds context afterWorld afterMemory) :
      OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
        afterMemory requirement

def OriginalWordEffectEvidence.toProtectedWordUpdate
    {context : StaticProofContext} {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    {requirement : OriginalStaticWordRequirement}
    (evidence : OriginalWordEffectEvidence context beforeWorld afterWorld
      beforeMemory afterMemory requirement) :
    OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
      afterMemory requirement := by
  cases evidence with
  | concreteWrites writes memoryExact avoids origins =>
      exact .concreteWrites writes memoryExact (.disjoint avoids origins)
  | symbolicWrites input behavior beforeExact afterExact avoids origins =>
      apply OriginalProtectedWordUpdate.concreteWrites
        (evalNormalizedWrites input behavior.writes)
      · calc
          afterMemory =
              ((behavior.eval input).nextMachineState input).memory := afterExact
          _ = applyConcreteWrites input.memory
              (evalNormalizedWrites input behavior.writes) := by
                rfl
          _ = applyConcreteWrites beforeMemory
              (evalNormalizedWrites input behavior.writes) := by
                rw [beforeExact]
      · exact .disjoint
          (normalizedWritesAvoidWord_of_checked
            requirement.slot.originalAddress input behavior.writes avoids)
          origins
  | x87Writes writes effect memoryExact writesAvoid x87Avoid origins =>
      apply OriginalProtectedWordUpdate.unchangedRead
      · calc
          Memory.read32 afterMemory requirement.slot.originalAddress =
              Memory.read32
                (applyX87MemoryEffect
                  (applyConcreteWrites beforeMemory writes) effect)
                requirement.slot.originalAddress := by rw [memoryExact]
          _ = Memory.read32 (applyConcreteWrites beforeMemory writes)
                requirement.slot.originalAddress :=
              Memory.read32_applyX87MemoryEffect_of_avoids _ _ _ x87Avoid
          _ = Memory.read32 beforeMemory requirement.slot.originalAddress :=
              Memory.read32_applyConcreteWrites_of_avoids _ _ _ writesAvoid
      · exact origins
  | unchangedRead readExact origins =>
      exact .unchangedRead readExact origins
  | relatedUpdate afterHolds =>
      exact .relatedUpdate afterHolds

/-- A singleton symbolic write is the common shape for stack spills and
arbitrary computed-address stores.  The address equality and closed
disjointness check are the only footprint-specific premises. -/
def OriginalWordEffectEvidence.symbolicSingleton
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement)
    (input : MachineState) (base : NormalizedSymbolicBehavior)
    (address value : Expr) (concreteAddress : Word)
    (beforeMemoryExact : input.memory = beforeMemory)
    (afterMemoryExact : afterMemory =
      ((({ base with writes := [(address, value)] } :
          NormalizedSymbolicBehavior).eval input).nextMachineState input).memory)
    (addressExact : address.eval input = concreteAddress)
    (disjoint : wordOffsetsDisjoint requirement.slot.originalAddress
      concreteAddress = true)
    (originsPreserved : requirement.OriginsPreserved context beforeWorld
      afterWorld) :
    OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  .symbolicWrites input
    ({ base with writes := [(address, value)] } :
      NormalizedSymbolicBehavior)
    beforeMemoryExact afterMemoryExact
    (normalizedWritesAvoidWordChecked_singleton
      requirement.slot.originalAddress input address value concreteAddress
      addressExact disjoint)
    originsPreserved

/-- Consume the exact normalized evaluator retained by an ordinary target
certificate.  The final-memory equality is stated against the checked decoded
behavior, so a detached symbolic summary cannot authorize this constructor. -/
def OriginalWordEffectEvidence.checkedOrdinary
    {pe : PE32} {program : Program}
    {targetId sourceRva : Nat}
    {record : ProgramRecord}
    {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe
      program targetId sourceRva record path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement)
    (input : MachineState) (calls : List Nat)
    (beforeMemoryExact : input.memory = beforeMemory)
    (afterMemoryExact : afterMemory =
      ((checked.toSuccessfulTargetEffectComponents.decodedBehavior input calls
        ).nextMachineState input).memory)
    (avoids : normalizedWritesAvoidWordChecked
      requirement.slot.originalAddress input (decoded.normalized calls).writes =
        true)
    (originsPreserved : requirement.OriginsPreserved context beforeWorld
      afterWorld) :
    OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  .symbolicWrites input (decoded.normalized calls) beforeMemoryExact
    (by simpa [CheckedOrdinaryTargetEffect.toSuccessfulTargetEffectComponents,
      ExactDecodedOrdinaryTargetEvaluator.behavior] using afterMemoryExact)
    avoids originsPreserved

/-- Consume an x87-bearing behavior from the checked target-effect interface.
Both the ordinary concrete prefix and the selected variable-width x87 store
must have checked disjoint footprints. -/
def OriginalWordEffectEvidence.checkedX87
    {program : Program} {targetId : Nat}
    (checked : CheckedOriginalTargetEffect program targetId)
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement)
    (input : MachineState) (calls : List Nat)
    (effect : StageA.X87.MachineEffect)
    (beforeMemoryExact : input.memory = beforeMemory)
    (afterMemoryExact : afterMemory =
      ((checked.components.decodedBehavior input calls).nextMachineState input).memory)
    (effectExact :
      (checked.components.decodedBehavior input calls).x87Effect = some effect)
    (writesAvoid : WritesAvoidWord requirement.slot.originalAddress
      (checked.components.decodedBehavior input calls).writes)
    (x87Avoid : X87MemoryEffectAvoidsWord
      requirement.slot.originalAddress effect)
    (originsPreserved : requirement.OriginsPreserved context beforeWorld
      afterWorld) :
    OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
      afterMemory requirement :=
  .x87Writes (checked.components.decodedBehavior input calls).writes effect
    (by
      calc
        afterMemory =
            ((checked.components.decodedBehavior input calls).nextMachineState
              input).memory := afterMemoryExact
        _ = applyX87MemoryEffect
              (applyConcreteWrites input.memory
                (checked.components.decodedBehavior input calls).writes)
              effect := by
                simp [RelationalBehavior.nextMachineState, effectExact]
        _ = applyX87MemoryEffect
              (applyConcreteWrites beforeMemory
                (checked.components.decodedBehavior input calls).writes)
              effect := by rw [beforeMemoryExact])
    writesAvoid x87Avoid originsPreserved

/-- External calls expose bounded machine-level footprints.  As with internal
effects, a stateful replacement must be proved explicitly. -/
inductive OriginalExternalWordEffectEvidence
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (requirement : OriginalStaticWordRequirement) : Prop where
  | footprints
      (supported : MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
      (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
        event.state.memory event.arguments requirement.slot.originalAddress)
      (originsPreserved : requirement.OriginsPreserved context event.world
        result.world) :
      OriginalExternalWordEffectEvidence context contract event result requirement
  | unchangedRead
      (readExact : Memory.read32 result.state.memory
          requirement.slot.originalAddress =
        Memory.read32 event.state.memory requirement.slot.originalAddress)
      (originsPreserved : requirement.OriginsPreserved context event.world
        result.world) :
      OriginalExternalWordEffectEvidence context contract event result requirement
  | relatedUpdate
      (afterHolds : requirement.Holds context result.world result.state.memory) :
      OriginalExternalWordEffectEvidence context contract event result requirement

def OriginalExternalWordEffectEvidence.toProtectedWordUpdate
    {context : StaticProofContext} {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    {requirement : OriginalStaticWordRequirement}
    (conforms : machineCallResultConforms false context contract event result)
    (evidence : OriginalExternalWordEffectEvidence context contract event result
      requirement) :
    OriginalProtectedWordUpdate context event.world result.world
      event.state.memory result.state.memory requirement := by
  cases evidence with
  | unchangedRead readExact origins => exact .unchangedRead readExact origins
  | relatedUpdate afterHolds => exact .relatedUpdate afterHolds
  | footprints supported avoids origins =>
      apply OriginalProtectedWordUpdate.unchangedRead
      · have direct : machineCallMemoryEffectHolds contract event.arguments
            event.state.memory result.state.memory := by
          have withWorld := conforms.2.2.1
          unfold machineCallMemoryEffectHoldsWithWorld at withWorld
          rcases supported with effect | effect | effect
          · simpa [effect] using withWorld
          · simpa [effect] using withWorld
          · simpa [effect] using withWorld
        exact machineCallMemoryEffectHolds_preservesWord contract
          event.arguments event.state.memory result.state.memory
          requirement.slot.originalAddress supported direct avoids
      · exact origins

/-- Complete finite inventory evidence.  Omitting any requirement makes this
structure uninhabited and therefore cannot preserve the inventory. -/
structure OriginalMemoryEffectInventoryEvidence
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory) : Prop where
  word : forall requirement, requirement ∈ inventory.requirements ->
    OriginalWordEffectEvidence context beforeWorld afterWorld beforeMemory
      afterMemory requirement

def OriginalMemoryEffectInventoryEvidence.toProtectedMemoryUpdate
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld afterWorld beforeMemory afterMemory) :
    OriginalProtectedMemoryUpdate context inventory beforeWorld afterWorld
      beforeMemory afterMemory where
  words requirement member :=
    (evidence.word requirement member).toProtectedWordUpdate

theorem OriginalMemoryEffectInventoryEvidence.preserves
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    (evidence : OriginalMemoryEffectInventoryEvidence context inventory
      beforeWorld afterWorld beforeMemory afterMemory)
    (before : inventory.HoldsIn context beforeWorld beforeMemory) :
    inventory.HoldsIn context afterWorld afterMemory :=
  evidence.toProtectedMemoryUpdate.preserves before

structure OriginalExternalMemoryInventoryEvidence
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult) : Prop where
  word : forall requirement, requirement ∈ inventory.requirements ->
    OriginalExternalWordEffectEvidence context contract event result requirement

def OriginalExternalMemoryInventoryEvidence.toProtectedMemoryUpdate
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    (conforms : machineCallResultConforms false context contract event result)
    (evidence : OriginalExternalMemoryInventoryEvidence context inventory
      contract event result) :
    OriginalProtectedMemoryUpdate context inventory event.world result.world
      event.state.memory result.state.memory where
  words requirement member :=
    (evidence.word requirement member).toProtectedWordUpdate conforms

theorem OriginalExternalMemoryInventoryEvidence.preserves
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {contract : MachineImportCallContract}
    {event : WorldExternalEvent} {result : WorldExternalResult}
    (conforms : machineCallResultConforms false context contract event result)
    (evidence : OriginalExternalMemoryInventoryEvidence context inventory
      contract event result)
    (before : inventory.HoldsIn context event.world event.state.memory) :
    inventory.HoldsIn context result.world result.state.memory :=
  (evidence.toProtectedMemoryUpdate conforms).preserves before

end StageA.Relational.OriginalMemoryEffectPreservation
