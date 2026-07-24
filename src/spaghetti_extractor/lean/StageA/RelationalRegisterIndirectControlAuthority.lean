import StageA.RelationalOriginalIndirectControlAuthority

namespace StageA.Relational.RegisterIndirectControlAuthority

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterTransfer
open StageA.Relational.OriginalIndirectControlAuthority

/-!
# Register-mediated original indirect-control authority

This module deliberately separates three facts which proposal tooling often
conflates:

* exact decoding of the indirect source and its continuation;
* the finite class from which the target value is obtained; and
* preservation or explicit restoration of the target register across every
  intervening call boundary.

The certificate is static and decidable.  The runtime witness is supplied by
segment, environment, callback, and launch proofs.  Consequently an untrusted
proposal can identify a likely source without authorizing an execution.
-/

structure ResolverQuery where
  resolver : ExternalTarget
  callRva : Nat
  identityRva : Nat
  identity : Bytes
  resourceId : Nat
deriving Repr, DecidableEq

inductive RegisterTargetInventory where
  | relocatedWritableCode (slotRva targetId : Nat)
  | importedAddress (iatRva : Nat) (imported : ExternalTarget)
  | resolverResults
      (queries : List ResolverQuery) (staticTargetIds : List Nat)
  | registeredCallbackSlot (slotRva : Nat) (targetIds : List Nat)
  | nullableCodeTable
      (startRva endRva : Nat) (entryTargetIds : List (Option Nat))
deriving Repr, DecidableEq

inductive RegisterProducerKind where
  | absoluteSlot (slotRva : Nat)
  | memoryLoad
  | resolverCall (resourceId : Nat)
  | immediateCode (targetId : Nat)
deriving Repr, DecidableEq

structure RegisterProducer where
  instructionRva : Nat
  instructionBytes : Bytes
  register : Reg
  kind : RegisterProducerKind
deriving Repr, DecidableEq

def noDuplicates [BEq α] (values : List α) : Bool :=
  values.length == values.eraseDups.length

def rvaInWritableNonExecutableSection (pe : PE32) (rva : Nat) : Bool :=
  pe.sections.any fun peSection =>
    peSection.writable && !peSection.executable &&
      peSection.virtualAddress <= rva &&
      rva < peSection.virtualAddress + peSection.mappedSize

/-- Check the loader-initialized value of one word while rejecting overlapping
section mappings.  Unlike `readExactRvaU32`, this deliberately accepts a word
in a section's virtual zero-fill tail. -/
def unambiguousInitialZeroWord (pe : PE32) (rva : Nat) : Bool :=
  match pe.sections.filter (fun peSection =>
      peSection.virtualAddress <= rva &&
        rva + 4 <= peSection.virtualAddress + peSection.mappedSize) with
  | [_] => readRvaU32 pe rva == some 0
  | _ => false

def importedTargetPresent
    (context : OriginalDecodedStaticContext) (target : ExternalTarget) : Bool :=
  context.imports.any fun imported => normalizeImport imported == target

def ResolverQuery.checked
    (context : OriginalDecodedStaticContext) (query : ResolverQuery) : Bool :=
  !query.identity.isEmpty &&
    importedTargetPresent context query.resolver &&
    exactRvaBytes context.pe query.identityRva (query.identity.length + 1) ==
      some (query.identity ++ [0])

def targetWord?
    (context : OriginalDecodedStaticContext) (targetId : Nat) : Option Nat := do
  let target <- context.codeMap.get? targetId
  if target.aliases.isEmpty && rvaInExecutableSection context.pe target.rva then
    some (context.pe.imageBase + target.rva)
  else
    none

def nullableTableEntriesChecked
    (context : OriginalDecodedStaticContext) (startRva : Nat)
    (entries : List (Option Nat)) : Bool :=
  entries.zipIdx.all fun (entry, index) =>
    let slotRva := startRva + index * 4
    match entry with
    | none =>
        readExactRvaU32 context.pe slotRva == some 0 &&
          relocationCountAt context.relocations slotRva == 0
    | some targetId =>
        relocationCountAt context.relocations slotRva == 1 &&
          match readExactRvaU32 context.pe slotRva,
              targetWord? context targetId with
          | some word, some targetWord => word == targetWord
          | _, _ => false

def absoluteSlotLoadInstruction
    (pe : PE32) (register : Reg) (slotRva : Nat) (bytes : Bytes) : Bool :=
  match decodeInstructionExact bytes with
  | some { instruction := .movFromOperand destination (.memory address), .. } =>
      destination == register && address.base.isNone && address.index.isNone &&
        address.displacement == pe.imageBase + slotRva
  | _ => false

def memoryLoadInstruction (register : Reg) (bytes : Bytes) : Bool :=
  match decodeInstructionExact bytes with
  | some { instruction := .load32 destination _ _, .. } =>
      destination == register
  | some { instruction := .movFromOperand destination (.memory _), .. } =>
      destination == register
  | _ => false

def resolverCallInstruction (register : Reg) (bytes : Bytes) : Bool :=
  match decodeInstructionExact bytes with
  | some { instruction := .callIndirect (.register source), .. } =>
      source == register
  | _ => false

def immediateCodeInstruction
    (context : OriginalDecodedStaticContext)
    (register : Reg) (targetId : Nat) (bytes : Bytes) : Bool :=
  match decodeInstructionExact bytes, targetWord? context targetId with
  | some { instruction := .movRegImm destination value, .. },
      some targetValue =>
      destination == register && value == targetValue
  | some {
      instruction := .movImmediate (.register destination) value, ..
    }, some targetValue =>
      destination == register &&
        value == targetValue
  | _, _ => false

def RegisterProducer.checked
    (context : OriginalDecodedStaticContext)
    (producer : RegisterProducer) : Bool :=
  !producer.instructionBytes.isEmpty &&
    exactRvaBytes context.pe producer.instructionRva
      producer.instructionBytes.length == some producer.instructionBytes &&
    match producer.kind with
    | .absoluteSlot slotRva =>
        absoluteSlotLoadInstruction context.pe producer.register slotRva
          producer.instructionBytes
    | .memoryLoad =>
        memoryLoadInstruction producer.register producer.instructionBytes
    | .resolverCall _ =>
        resolverCallInstruction producer.register producer.instructionBytes
    | .immediateCode targetId =>
        immediateCodeInstruction context producer.register targetId
          producer.instructionBytes

def hasProducer
    (producers : List RegisterProducer) (kind : RegisterProducerKind) : Bool :=
  producers.any fun producer => producer.kind == kind

def hasResolverProducer
    (producers : List RegisterProducer) (query : ResolverQuery) : Bool :=
  producers.any fun producer =>
    producer.instructionRva == query.callRva &&
      producer.kind == .resolverCall query.resourceId

def RegisterTargetInventory.producersComplete
    (producers : List RegisterProducer) : RegisterTargetInventory -> Bool
  | .relocatedWritableCode slotRva _ =>
      hasProducer producers (.absoluteSlot slotRva)
  | .importedAddress iatRva _ =>
      hasProducer producers (.absoluteSlot iatRva)
  | .resolverResults queries staticTargetIds =>
      (queries.all fun query =>
        hasResolverProducer producers query) &&
      staticTargetIds.all fun targetId =>
        hasProducer producers (.immediateCode targetId)
  | .registeredCallbackSlot slotRva _ =>
      hasProducer producers (.absoluteSlot slotRva)
  | .nullableCodeTable _ _ _ =>
      hasProducer producers .memoryLoad

def RegisterTargetInventory.checked
    (context : OriginalDecodedStaticContext) :
    RegisterTargetInventory -> Bool
  | .relocatedWritableCode slotRva targetId =>
      rvaInWritableNonExecutableSection context.pe slotRva &&
        ({ slotRva, targetId } : RelocatedCodePointerSeed).checked context
  | .importedAddress _ imported =>
      importedTargetPresent context imported
  | .resolverResults queries staticTargetIds =>
      !queries.isEmpty &&
        noDuplicates (queries.map ResolverQuery.callRva) &&
        noDuplicates (queries.map ResolverQuery.resourceId) &&
        queries.all (ResolverQuery.checked context) &&
        (staticTargetIds.isEmpty ||
          codeTargetInventoryChecked context staticTargetIds)
  | .registeredCallbackSlot slotRva targetIds =>
      slotRva % 4 == 0 &&
        rvaInWritableNonExecutableSection context.pe slotRva &&
        unambiguousInitialZeroWord context.pe slotRva &&
        relocationCountAt context.relocations slotRva == 0 &&
        (targetIds.isEmpty || codeTargetInventoryChecked context targetIds)
  | .nullableCodeTable startRva endRva entries =>
      startRva % 4 == 0 && endRva % 4 == 0 && startRva < endRva &&
        endRva - startRva == entries.length * 4 &&
        nullableTableEntriesChecked context startRva entries

inductive RegisterCarryKind where
  | internalCall (calleeTargetId : Nat)
  | machineImport (contractId : Nat)
  | targetCall
  | stackRestore
      (saveRva : Nat) (saveBytes : Bytes)
      (restoreRva : Nat) (restoreBytes : Bytes)
deriving Repr, DecidableEq

structure RegisterCarryBoundary where
  sourceTargetId : Nat
  instructionRva : Nat
  instructionBytes : Bytes
  continuationTargetId : Nat
  register : Reg
  kind : RegisterCarryKind
deriving Repr, DecidableEq

def callInstruction (bytes : Bytes) : Bool :=
  match decodeInstructionExact bytes with
  | some { instruction := .callRel32 _, .. }
  | some { instruction := .callImport _, .. }
  | some { instruction := .callIndirect _, .. } => true
  | _ => false

def stackSaveAddress?
    (bytes : Bytes) (register : Reg) : Option Addressing :=
  match decodeInstructionExact bytes with
  | some { instruction := .movToOperand (.memory address) source, .. } =>
      if source == register && address.base == some .esp &&
          address.index.isNone then some address else none
  | _ => none

def stackRestoreAddress?
    (bytes : Bytes) (register : Reg) : Option Addressing :=
  match decodeInstructionExact bytes with
  | some { instruction := .movFromOperand destination (.memory address), .. } =>
      if destination == register && address.base == some .esp &&
          address.index.isNone then some address else none
  | _ => none

def stackRestoreChecked
    (context : OriginalDecodedStaticContext)
    (boundary : RegisterCarryBoundary)
    (saveRva : Nat) (saveBytes : Bytes)
    (restoreRva : Nat) (restoreBytes : Bytes) : Bool :=
  !saveBytes.isEmpty && !restoreBytes.isEmpty &&
    exactRvaBytes context.pe saveRva saveBytes.length == some saveBytes &&
    exactRvaBytes context.pe restoreRva restoreBytes.length == some restoreBytes &&
    saveRva + saveBytes.length <= boundary.instructionRva &&
    boundary.instructionRva + boundary.instructionBytes.length <= restoreRva &&
    match stackSaveAddress? saveBytes boundary.register,
        stackRestoreAddress? restoreBytes boundary.register with
    | some saveAddress, some restoreAddress => saveAddress == restoreAddress
    | _, _ => false

def RegisterCarryBoundary.contractChecked
    (context : OriginalDecodedStaticContext)
    (boundary : RegisterCarryBoundary) : Bool :=
  match boundary.kind with
  | .machineImport contractId =>
      context.machineImportCallContracts.any fun contract =>
        contract.id == contractId &&
          contract.preservedRegisters.contains boundary.register
  | .internalCall calleeTargetId =>
      (context.codeMap.get? calleeTargetId).isSome
  | .targetCall => true
  | .stackRestore saveRva saveBytes restoreRva restoreBytes =>
      stackRestoreChecked context boundary
        saveRva saveBytes restoreRva restoreBytes

def RegisterCarryBoundary.checked
    (context : OriginalDecodedStaticContext)
    (boundary : RegisterCarryBoundary) : Bool :=
  !boundary.instructionBytes.isEmpty &&
    exactRvaBytes context.pe boundary.instructionRva
      boundary.instructionBytes.length == some boundary.instructionBytes &&
    callInstruction boundary.instructionBytes &&
    match context.source? boundary.sourceTargetId,
        context.codeMap.get? boundary.continuationTargetId with
    | some source, some continuation =>
        source.region.span.start <= boundary.instructionRva &&
          boundary.instructionRva + boundary.instructionBytes.length <=
            source.region.span.start + source.region.span.size &&
          continuation.rva ==
            boundary.instructionRva + boundary.instructionBytes.length &&
          boundary.contractChecked context
    | _, _ => false

structure Certificate where
  site : OriginalIndirectControlSite
  register : Reg
  inventory : RegisterTargetInventory
  producers : List RegisterProducer
  carries : List RegisterCarryBoundary
deriving Repr, DecidableEq

def Certificate.checked
    (context : OriginalDecodedStaticContext) (certificate : Certificate) : Bool :=
  certificate.site.target == .register certificate.register &&
    certificate.site.checked context &&
    certificate.inventory.checked context &&
    !certificate.producers.isEmpty &&
    noDuplicates (certificate.producers.map fun producer =>
      (producer.instructionRva, producer.register, producer.kind)) &&
    certificate.producers.all (RegisterProducer.checked context) &&
    certificate.inventory.producersComplete certificate.producers &&
    noDuplicates (certificate.carries.map fun carry =>
      (carry.sourceTargetId, carry.instructionRva, carry.register)) &&
    certificate.carries.all fun carry =>
      carry.register == certificate.register && carry.checked context

structure CheckedCertificate
    (context : OriginalDecodedStaticContext) where
  authority : ExactOriginalDecodedAuthority context
  certificate : Certificate
  checked : certificate.checked context = true

inductive RuntimeTargetMember
    (context : OriginalDecodedStaticContext) (world : RelationalWorld)
    (value : Word) : RegisterTargetInventory -> Prop
  | relocatedWritableCode
      (slotRva targetId : Nat) (target : OriginalCodeTarget)
      (found : context.codeMap.get? targetId = some target)
      (valueExact :
        value = BitVec.ofNat 32 (context.pe.imageBase + target.rva)) :
      RuntimeTargetMember context world value
        (.relocatedWritableCode slotRva targetId)
  | importedAddress
      (iatRva : Nat) (imported : ExternalTarget) (binding : ImportAddressPair)
      (member : binding ∈ world.importAddresses)
      (identity : binding.imported = imported)
      (iatExact : binding.originalIatRva = iatRva)
      (valueExact : value = binding.originalAddress) :
      RuntimeTargetMember context world value (.importedAddress iatRva imported)
  | resolverResult
      (queries : List ResolverQuery) (staticTargetIds : List Nat)
      (query : ResolverQuery) (resource : OpaqueResourcePair)
      (queryMember : query ∈ queries)
      (member : resource ∈ world.opaqueResources)
      (allowed : resource.id = query.resourceId)
      (valueExact : value = resource.original) :
      RuntimeTargetMember context world value
        (.resolverResults queries staticTargetIds)
  | resolverStaticTarget
      (queries : List ResolverQuery) (staticTargetIds : List Nat)
      (targetId : Nat) (target : OriginalCodeTarget)
      (allowed : targetId ∈ staticTargetIds)
      (found : context.codeMap.get? targetId = some target)
      (valueExact :
        value = BitVec.ofNat 32 (context.pe.imageBase + target.rva)) :
      RuntimeTargetMember context world value
        (.resolverResults queries staticTargetIds)
  | registeredCallback
      (slotRva : Nat) (targetIds : List Nat)
      (callback : RegisteredCallbackPair)
      (member : callback ∈ world.registeredCallbacks)
      (allowed : callback.targetId ∈ targetIds)
      (target : OriginalCodeTarget)
      (found : context.codeMap.get? callback.targetId = some target)
      (valueExact : value = callback.originalAddress) :
      RuntimeTargetMember context world value
        (.registeredCallbackSlot slotRva targetIds)
  | nullableTable
      (startRva endRva : Nat) (entries : List (Option Nat))
      (index targetId : Nat) (target : OriginalCodeTarget)
      (indexBound : index < entries.length)
      (entry : entries[index]? = some (some targetId))
      (found : context.codeMap.get? targetId = some target)
      (valueExact :
        value = BitVec.ofNat 32 (context.pe.imageBase + target.rva)) :
      RuntimeTargetMember context world value
        (.nullableCodeTable startRva endRva entries)

structure RegisterCarryExecution
    (context : OriginalDecodedStaticContext)
    (boundary : RegisterCarryBoundary) where
  beforeEip : Word
  afterEip : Word
  before : MachineState
  after : MachineState
  sourceExact :
    beforeEip.toNat = context.pe.imageBase +
      match boundary.kind with
      | .stackRestore saveRva _ _ _ => saveRva
      | _ => boundary.instructionRva
  continuationExact :
    afterEip.toNat = context.pe.imageBase +
      match boundary.kind with
      | .stackRestore _ _ restoreRva restoreBytes =>
          restoreRva + restoreBytes.length
      | _ => boundary.instructionRva + boundary.instructionBytes.length
  registerPreserved :
    after.registers.get boundary.register =
      before.registers.get boundary.register

structure SomeRegisterCarryExecution
    (context : OriginalDecodedStaticContext) where
  boundary : RegisterCarryBoundary
  execution : RegisterCarryExecution context boundary

structure RuntimeClosure
    (context : OriginalDecodedStaticContext)
    (certificate : Certificate)
    (world : RelationalWorld) (sourceEip : Word) (state : MachineState) where
  sourceExact :
    sourceEip.toNat = context.pe.imageBase + certificate.site.instructionRva
  carryExecutions : List (SomeRegisterCarryExecution context)
  carryInventory :
    carryExecutions.map (fun execution =>
      (execution.boundary.sourceTargetId, execution.boundary.instructionRva,
        execution.boundary.register)) =
      certificate.carries.map (fun boundary =>
        (boundary.sourceTargetId, boundary.instructionRva, boundary.register))
  targetMember :
    RuntimeTargetMember context world
      (state.registers.get certificate.register) certificate.inventory

structure CheckedAuthority
    (context : OriginalDecodedStaticContext) where
  certificate : CheckedCertificate context
  reachable : RelationalWorld -> Word -> MachineState -> Prop
  runtime :
    ∀ world sourceEip state,
      reachable world sourceEip state ->
      sourceEip.toNat =
        context.pe.imageBase + certificate.certificate.site.instructionRva ->
      RuntimeClosure context certificate.certificate world sourceEip state

theorem CheckedAuthority.targetClosed
    (authority : CheckedAuthority context)
    (world : RelationalWorld) (sourceEip : Word) (state : MachineState)
    (reachable : authority.reachable world sourceEip state)
    (atSource :
      sourceEip.toNat = context.pe.imageBase +
        authority.certificate.certificate.site.instructionRva) :
    RuntimeTargetMember context world
      (state.registers.get authority.certificate.certificate.register)
      authority.certificate.certificate.inventory :=
  (authority.runtime world sourceEip state reachable atSource).targetMember

theorem RegisterCarryExecution.carries
    (execution : RegisterCarryExecution context boundary) :
    execution.after.registers.get boundary.register =
      execution.before.registers.get boundary.register :=
  execution.registerPreserved

#print axioms CheckedAuthority.targetClosed
#print axioms RegisterCarryExecution.carries

end StageA.Relational.RegisterIndirectControlAuthority
