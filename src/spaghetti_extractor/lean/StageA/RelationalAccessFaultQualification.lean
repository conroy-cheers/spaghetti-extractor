import StageA.RelationalInterpreterTransfer
import StageA.RelationalInterpreterX87
import StageA.RelationalISAQualification

namespace StageA.Relational.AccessFaultQualification

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterX87

/-! This module qualifies the modeled access/fault dimension only.  In
particular, a modeled access is not an architectural no-fault claim; the
separate `FlatMappedAccessLaunchAssumption` remains the required bridge to a
concrete launch environment. -/

def regionSpanOn (side : RelationalSide)
    (region : RegionRelation) : Span :=
  match side with
  | .original => region.original
  | .candidate => region.candidate

inductive TransitionFaultClass where
  | notFault
  | divideError
  | memoryFault
  | externalFault
  | unimplemented
deriving Repr, DecidableEq

def completionFaultClass : Completion -> TransitionFaultClass
  | .divideError => .divideError
  | .memoryFault => .memoryFault
  | .externalFault => .externalFault
  | .unimplemented => .unimplemented
  | _ => .notFault

def faultClassIsFault : TransitionFaultClass -> Bool
  | .notFault => false
  | _ => true

theorem faultCompletion_eq_faultClassIsFault (completion : Completion) :
    faultCompletion completion =
      faultClassIsFault (completionFaultClass completion) := by
  cases completion <;> rfl

def actionIntroducesDivideFault : SemanticAction -> Bool
  | .divideIf _ => true
  | _ => false

def actionInvokesCall : SemanticAction -> Bool
  | .call _ => true
  | _ => false

def permittedFaultClasses
    (transfer : SemanticTransfer) : List TransitionFaultClass :=
  if transfer.body.any actionInvokesCall then
    [.notFault, .divideError, .memoryFault, .externalFault, .unimplemented]
  else if transfer.body.any actionIntroducesDivideFault then
    [.notFault, .divideError]
  else
    [.notFault]

/-! Calls carry no direct flat-memory footprint in this layer: their successor
state and external effects are qualified by the paired environment. REP
effects are represented by counted runtime events. A malformed load rejects
instead of silently disappearing from the footprint. -/
def accessFaultActionSupported
    (transfer : SemanticTransfer) : SemanticAction -> Bool
  | .evalWord nodeIndex =>
      match transfer.wordNodes[nodeIndex]? with
      | none => false
      | some node =>
          match node.op with
          | .load =>
              match node.args, MemoryWidth.ofBytes? node.aux with
              | [_], some _ => true
              | _, _ => false
          | _ => true
  | _ => true

def accessFaultShapeChecked
    (transfer : SemanticTransfer) : Bool :=
  transfer.body.all (accessFaultActionSupported transfer)

def accessFaultSiteSupported
    (site : FlatMemoryAccessSite) : Bool :=
  site.addressNode.isSome && site.valueNode.isSome

structure AccessFaultFormCertificate where
  occurrence : InstructionFormOccurrence
  footprint : List FlatMemoryAccessSite
  permittedFaults : List TransitionFaultClass
deriving Repr, DecidableEq

def instructionOccurrenceSpan
    (occurrence : InstructionFormOccurrence) : Span := {
  start := occurrence.offset
  size := occurrence.size
}

def AccessFaultFormCertificate.checked
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (record : ProgramRecord)
    (transfer : SemanticTransfer) : Bool :=
    certificate.occurrence.size > 0 &&
    certificate.occurrence.size <= 15 &&
    certificate.occurrence.bytes.length == certificate.occurrence.size &&
    wholeSpanContainedChecked
      (regionSpanOn side region).start (regionSpanOn side region).size
      certificate.occurrence.offset certificate.occurrence.size &&
    decodeInstructionFormsSpan (context.peOn side)
      (instructionOccurrenceSpan certificate.occurrence) ==
        some [certificate.occurrence] &&
    record.decode == some transfer &&
    transfer.checked &&
    transfer.sourceRva == certificate.occurrence.offset &&
    flatMemoryFootprintChecked transfer certificate.footprint &&
    certificate.footprint.all accessFaultSiteSupported &&
    accessFaultShapeChecked transfer &&
    certificate.permittedFaults == permittedFaultClasses transfer

structure DecodedAccessFaultFormSemantics
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (record : ProgramRecord)
    (transfer : SemanticTransfer) : Prop where
  sizePositive : certificate.occurrence.size > 0
  instructionSizeBounded : certificate.occurrence.size <= 15
  bytesExact :
    certificate.occurrence.bytes.length = certificate.occurrence.size
  containedInRegion :
    AccessSpanContained
      (regionSpanOn side region).start (regionSpanOn side region).size
      certificate.occurrence.offset certificate.occurrence.size
  instructionDecoded :
    decodeInstructionFormsSpan (context.peOn side)
      (instructionOccurrenceSpan certificate.occurrence) =
        some [certificate.occurrence]
  recordDecoded : record.decode = some transfer
  transferChecked : transfer.checked = true
  sourceExact : transfer.sourceRva = certificate.occurrence.offset
  footprintExact :
    certificate.footprint = orderedFlatMemoryFootprint transfer
  footprintSupported :
    certificate.footprint.all accessFaultSiteSupported = true
  actionShapeSupported : accessFaultShapeChecked transfer = true
  faultsExact :
    certificate.permittedFaults = permittedFaultClasses transfer

theorem AccessFaultFormCertificate.checked_sound
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (record : ProgramRecord)
    (transfer : SemanticTransfer)
    (checked :
      certificate.checked side context region record transfer = true) :
    DecodedAccessFaultFormSemantics certificate side context region record
      transfer := by
  simp only [AccessFaultFormCertificate.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq, flatMemoryFootprintChecked] at checked
  rcases checked with ⟨checked, faultsExact⟩
  rcases checked with ⟨checked, actionShapeSupported⟩
  rcases checked with ⟨checked, footprintSupported⟩
  rcases checked with ⟨checked, footprintExact⟩
  rcases checked with ⟨checked, sourceExact⟩
  rcases checked with ⟨checked, transferChecked⟩
  rcases checked with ⟨checked, recordDecoded⟩
  rcases checked with ⟨checked, instructionDecoded⟩
  rcases checked with ⟨checked, containedInRegion⟩
  rcases checked with ⟨checked, bytesExact⟩
  rcases checked with ⟨sizePositive, instructionSizeBounded⟩
  refine {
    sizePositive := sizePositive
    instructionSizeBounded := instructionSizeBounded
    bytesExact := bytesExact
    containedInRegion := wholeSpanContainedChecked_sound _ _ _ _
      containedInRegion
    instructionDecoded := instructionDecoded
    recordDecoded := recordDecoded
    transferChecked := transferChecked
    sourceExact := sourceExact
    footprintExact := footprintExact
    footprintSupported := footprintSupported
    actionShapeSupported := actionShapeSupported
    faultsExact := faultsExact
  }

structure AccessFaultRegionCertificate where
  regionId : Nat
  forms : List AccessFaultFormCertificate
deriving Repr, DecidableEq

def accessFaultFormBindingsChecked
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) :
    List AccessFaultFormCertificate -> List ProgramRecord ->
      List SemanticTransfer -> Bool
  | [], [], [] => true
  | certificate :: certificates, record :: records, transfer :: transfers =>
      certificate.checked side context region record transfer &&
        accessFaultFormBindingsChecked side context region
          certificates records transfers
  | _, _, _ => false

def AllDecodedAccessFaultFormSemantics
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) :
    List AccessFaultFormCertificate -> List ProgramRecord ->
      List SemanticTransfer -> Prop
  | [], [], [] => True
  | certificate :: certificates, record :: records, transfer :: transfers =>
      DecodedAccessFaultFormSemantics certificate side context region record
        transfer ∧
      AllDecodedAccessFaultFormSemantics side context region
        certificates records transfers
  | _, _, _ => False

theorem accessFaultFormBindingsChecked_sound
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) :
    ∀ certificates records transfers,
      accessFaultFormBindingsChecked side context region
        certificates records transfers = true ->
      AllDecodedAccessFaultFormSemantics side context region
        certificates records transfers := by
  intro certificates
  induction certificates with
  | nil =>
      intro records transfers checked
      cases records <;> cases transfers <;>
        simp_all [accessFaultFormBindingsChecked,
          AllDecodedAccessFaultFormSemantics]
  | cons certificate certificates ih =>
      intro records transfers checked
      cases records with
      | nil => simp [accessFaultFormBindingsChecked] at checked
      | cons record records =>
          cases transfers with
          | nil => simp [accessFaultFormBindingsChecked] at checked
          | cons transfer transfers =>
              simp only [accessFaultFormBindingsChecked, Bool.and_eq_true]
                at checked
              exact ⟨certificate.checked_sound side context region record
                transfer checked.1, ih records transfers checked.2⟩

def AccessFaultRegionCertificate.checked
    (certificate : AccessFaultRegionCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (records : List ProgramRecord)
    (transfers : List SemanticTransfer) : Bool :=
  certificate.regionId == region.id &&
    certificate.forms.length > 0 &&
    decodeInstructionFormsSpan (context.peOn side) (regionSpanOn side region) ==
      some (certificate.forms.map AccessFaultFormCertificate.occurrence) &&
    accessFaultFormBindingsChecked side context region
      certificate.forms records transfers

structure DecodedAccessFaultRegionSemantics
    (certificate : AccessFaultRegionCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (records : List ProgramRecord)
    (transfers : List SemanticTransfer) : Prop where
  regionIdExact : certificate.regionId = region.id
  formsNonempty : certificate.forms ≠ []
  regionDecoded :
    decodeInstructionFormsSpan (context.peOn side) (regionSpanOn side region) =
      some (certificate.forms.map AccessFaultFormCertificate.occurrence)
  formsDecoded :
    AllDecodedAccessFaultFormSemantics side context region
      certificate.forms records transfers

theorem AccessFaultRegionCertificate.checked_sound
    (certificate : AccessFaultRegionCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) (records : List ProgramRecord)
    (transfers : List SemanticTransfer)
    (checked :
      certificate.checked side context region records transfers = true) :
    DecodedAccessFaultRegionSemantics certificate side context region records
      transfers := by
  simp only [AccessFaultRegionCertificate.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with ⟨checked, formsDecoded⟩
  rcases checked with ⟨checked, regionDecoded⟩
  rcases checked with ⟨regionIdExact, formsLengthPositive⟩
  exact {
    regionIdExact := regionIdExact
    formsNonempty := by
      intro empty
      simp [empty] at formsLengthPositive
    regionDecoded := regionDecoded
    formsDecoded := accessFaultFormBindingsChecked_sound side context region
      certificate.forms records transfers formsDecoded
  }

def transitionAccessFaultChecked
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (result : MacroResult) : Bool :=
  interpreterEventsAccessDomainChecked side context world result.events &&
    certificate.permittedFaults.contains
      (completionFaultClass result.completion)

structure TransitionAccessFaultSemantics
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (result : MacroResult) : Prop where
  accessesModeled :
    ∀ event ∈ result.events,
      InterpreterEventModeledAccessDomain side context world event
  faultClaimed :
    completionFaultClass result.completion ∈ certificate.permittedFaults
  faultSemanticsExact :
    faultCompletion result.completion =
      faultClassIsFault (completionFaultClass result.completion)

theorem transitionAccessFaultChecked_sound
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (result : MacroResult)
    (checked :
      transitionAccessFaultChecked certificate side context world result =
        true) :
    TransitionAccessFaultSemantics certificate side context world result := by
  simp only [transitionAccessFaultChecked, Bool.and_eq_true] at checked
  exact {
    accessesModeled := interpreterEventsAccessDomainChecked_sound side context
      world result.events checked.1
    faultClaimed := List.contains_iff_mem.mp checked.2
    faultSemanticsExact :=
      faultCompletion_eq_faultClassIsFault result.completion
  }

/-! This is the typed authority consumed by later integration.  The transition
field must prove a proposition about the exact decoded transfer execution under
an explicit admissibility predicate.  A theorem whose type is merely `True`
cannot inhabit this structure. -/
structure TypedAccessFaultQualification
    (StateAdmissible :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Prop)
    (certificate : AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (region : RegionRelation)
    (record : ProgramRecord) (transfer : SemanticTransfer) : Prop where
  decodedChecked :
    certificate.checked side context region record transfer = true
  transitionsChecked :
    ∀ environment state result,
      StateAdmissible environment state ->
      transfer.execute environment state = some result ->
      transitionAccessFaultChecked certificate side context world result = true

theorem TypedAccessFaultQualification.decodedSemantics
    {StateAdmissible :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Prop}
    {certificate : AccessFaultFormCertificate}
    {side : RelationalSide} {context : StaticProofContext}
    {world : RelationalWorld} {region : RegionRelation}
    {record : ProgramRecord} {transfer : SemanticTransfer}
    (qualification : TypedAccessFaultQualification StateAdmissible certificate
      side context world region record transfer) :
    DecodedAccessFaultFormSemantics certificate side context region record
      transfer :=
  certificate.checked_sound side context region record transfer
    qualification.decodedChecked

theorem TypedAccessFaultQualification.transitionSemantics
    {StateAdmissible :
      StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Prop}
    {certificate : AccessFaultFormCertificate}
    {side : RelationalSide} {context : StaticProofContext}
    {world : RelationalWorld} {region : RegionRelation}
    {record : ProgramRecord} {transfer : SemanticTransfer}
    (qualification : TypedAccessFaultQualification StateAdmissible certificate
      side context world region record transfer)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : InterpreterMachine) (result : MacroResult)
    (admissible : StateAdmissible environment state)
    (executed : transfer.execute environment state = some result) :
    TransitionAccessFaultSemantics certificate side context world result :=
  transitionAccessFaultChecked_sound certificate side context world result
    (qualification.transitionsChecked environment state result admissible
      executed)

/-! x87 singleton records deliberately do not decode through
`ProgramRecord.decode`: their authoritative execution path is the exact
physical x87 replay model.  The following parallel certificate binds the same
ISA occurrence and modeled-memory/fault claims directly to that executor. -/

structure X87AccessFaultFormCertificate where
  occurrence : InstructionFormOccurrence
deriving Repr, DecidableEq

def X87AccessFaultFormCertificate.record
    (certificate : X87AccessFaultFormCertificate) : RawInstructionRecord := {
  index := 0
  kind := 1
  span := instructionOccurrenceSpan certificate.occurrence
  bytes := certificate.occurrence.bytes
  bytesSha256 := ""
  canonicalBytes := []
  recordSha256 := ""
  transferBytesSha256 := ""
}

def X87AccessFaultFormCertificate.checked
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) : Bool :=
  let record := certificate.record
  certificate.occurrence.size > 0 &&
    certificate.occurrence.size <= 15 &&
    certificate.occurrence.bytes.length == certificate.occurrence.size &&
    wholeSpanContainedChecked
      (regionSpanOn side region).start (regionSpanOn side region).size
      certificate.occurrence.offset certificate.occurrence.size &&
    decodeInstructionFormsSpan (context.peOn side)
      (instructionOccurrenceSpan certificate.occurrence) ==
        some [certificate.occurrence] &&
    record.decodeClass == some .x87Singleton &&
    record.exactPEChecked (context.peOn side) &&
    record.semanticClassChecked &&
    (StageA.Relational.X87.decodeSingletonCommand
      (context.peOn side) record.span).isSome

structure DecodedX87AccessFaultFormSemantics
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation) : Prop where
  sizePositive : certificate.occurrence.size > 0
  instructionSizeBounded : certificate.occurrence.size <= 15
  bytesExact :
    certificate.occurrence.bytes.length = certificate.occurrence.size
  containedInRegion :
    AccessSpanContained
      (regionSpanOn side region).start (regionSpanOn side region).size
      certificate.occurrence.offset certificate.occurrence.size
  instructionDecoded :
    decodeInstructionFormsSpan (context.peOn side)
      (instructionOccurrenceSpan certificate.occurrence) =
        some [certificate.occurrence]
  recordClass :
    certificate.record.decodeClass = some .x87Singleton
  recordBytesExact :
    certificate.record.exactPEChecked (context.peOn side) = true
  semanticClass :
    certificate.record.semanticClassChecked = true
  commandDecoded :
    (StageA.Relational.X87.decodeSingletonCommand
      (context.peOn side) certificate.record.span).isSome = true

theorem X87AccessFaultFormCertificate.checked_sound
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (region : RegionRelation)
    (checked : certificate.checked side context region = true) :
    DecodedX87AccessFaultFormSemantics certificate side context region := by
  simp only [X87AccessFaultFormCertificate.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with ⟨checked, commandDecoded⟩
  rcases checked with ⟨checked, semanticClass⟩
  rcases checked with ⟨checked, recordBytesExact⟩
  rcases checked with ⟨checked, recordClass⟩
  rcases checked with ⟨checked, instructionDecoded⟩
  rcases checked with ⟨checked, containedInRegion⟩
  rcases checked with ⟨checked, bytesExact⟩
  rcases checked with ⟨sizePositive, instructionSizeBounded⟩
  exact {
    sizePositive := sizePositive
    instructionSizeBounded := instructionSizeBounded
    bytesExact := bytesExact
    containedInRegion := wholeSpanContainedChecked_sound _ _ _ _
      containedInRegion
    instructionDecoded := instructionDecoded
    recordClass := recordClass
    recordBytesExact := recordBytesExact
    semanticClass := semanticClass
    commandDecoded := commandDecoded
  }

def x87MemoryEffectAccessDomainChecked
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) : MemoryEffect -> Bool
  | .read address bytes _ =>
      bytes > 0 &&
        relationalAccessSpanChecked side context world .read
          address.toNat bytes
  | .write address bytes _ =>
      bytes > 0 &&
        relationalAccessSpanChecked side context world .write
          address.toNat bytes

def x87MemoryEffectsAccessDomainChecked
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (effects : List MemoryEffect) : Bool :=
  effects.all (x87MemoryEffectAccessDomainChecked side context world)

def X87MemoryEffectModeledAccessDomain
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (effect : MemoryEffect) : Prop :=
  x87MemoryEffectAccessDomainChecked side context world effect = true

theorem x87MemoryEffectsAccessDomainChecked_sound
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (effects : List MemoryEffect)
    (checked :
      x87MemoryEffectsAccessDomainChecked side context world effects = true) :
    ∀ effect ∈ effects,
      X87MemoryEffectModeledAccessDomain side context world effect := by
  intro effect member
  simp only [x87MemoryEffectsAccessDomainChecked, List.all_eq_true] at checked
  exact checked effect member

def x87ScheduleFaultSupported : ScheduleFault -> Bool
  | .x87 _ => true
  | _ => false

def x87TransitionAccessFaultChecked
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (result : StepResult) : Bool :=
  x87MemoryEffectsAccessDomainChecked side context world result.memoryEffects &&
    result.faults.all x87ScheduleFaultSupported &&
    result.calls.isEmpty &&
    result.control == .fallthrough
      (instructionOccurrenceSpan certificate.occurrence).stop &&
    result.x87Response.isSome

structure X87TransitionAccessFaultSemantics
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (state : MachineState)
    (result : StepResult) : Prop where
  accessesModeled :
    ∀ effect ∈ result.memoryEffects,
      X87MemoryEffectModeledAccessDomain side context world effect
  faultsTyped : result.faults.all x87ScheduleFaultSupported = true
  noCalls : result.calls = []
  exactControl : result.control = .fallthrough
    (instructionOccurrenceSpan certificate.occurrence).stop
  responsePresent : result.x87Response.isSome = true
  executionExact :
    executeX87Singleton (context.peOn side) certificate.record state =
      some result
  physicalFields : PhysicalX87FieldsEstablished result

theorem x87TransitionAccessFaultChecked_sound
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (state : MachineState) (result : StepResult)
    (executed :
      executeX87Singleton (context.peOn side) certificate.record state =
        some result)
    (checked :
      x87TransitionAccessFaultChecked certificate side context world result =
        true) :
    X87TransitionAccessFaultSemantics certificate side context world state
      result := by
  simp only [x87TransitionAccessFaultChecked, Bool.and_eq_true,
    beq_iff_eq, List.isEmpty_iff] at checked
  rcases checked with
    ⟨⟨⟨⟨accessesModeled, faultsTyped⟩, noCalls⟩, exactControl⟩,
      responsePresent⟩
  exact {
    accessesModeled := x87MemoryEffectsAccessDomainChecked_sound side context
      world result.memoryEffects accessesModeled
    faultsTyped := faultsTyped
    noCalls := noCalls
    exactControl := exactControl
    responsePresent := responsePresent
    executionExact := executed
    physicalFields :=
      (executeX87Singleton_witness
        (context.peOn side) certificate.record state result executed).physicalFields
  }

structure TypedX87AccessFaultQualification
    (StateAdmissible : MachineState -> Prop)
    (certificate : X87AccessFaultFormCertificate)
    (side : RelationalSide) (context : StaticProofContext)
    (world : RelationalWorld) (region : RegionRelation) : Prop where
  decodedChecked : certificate.checked side context region = true
  transitionsChecked :
    ∀ state result,
      StateAdmissible state ->
      executeX87Singleton (context.peOn side) certificate.record state =
        some result ->
      x87TransitionAccessFaultChecked certificate side context world result =
        true

theorem TypedX87AccessFaultQualification.decodedSemantics
    {StateAdmissible : MachineState -> Prop}
    {certificate : X87AccessFaultFormCertificate}
    {side : RelationalSide} {context : StaticProofContext}
    {world : RelationalWorld} {region : RegionRelation}
    (qualification : TypedX87AccessFaultQualification StateAdmissible
      certificate side context world region) :
    DecodedX87AccessFaultFormSemantics certificate side context region :=
  certificate.checked_sound side context region qualification.decodedChecked

theorem TypedX87AccessFaultQualification.transitionSemantics
    {StateAdmissible : MachineState -> Prop}
    {certificate : X87AccessFaultFormCertificate}
    {side : RelationalSide} {context : StaticProofContext}
    {world : RelationalWorld} {region : RegionRelation}
    (qualification : TypedX87AccessFaultQualification StateAdmissible
      certificate side context world region)
    (state : MachineState) (result : StepResult)
    (admissible : StateAdmissible state)
    (executed :
      executeX87Singleton (context.peOn side) certificate.record state =
        some result) :
    X87TransitionAccessFaultSemantics certificate side context world state
      result :=
  x87TransitionAccessFaultChecked_sound certificate side context world state
    result executed
    (qualification.transitionsChecked state result admissible executed)

end StageA.Relational.AccessFaultQualification
