import StageA.RelationalEnvironment

namespace StageA.Relational.StaticMachineImportContracts

open StageA.Formal StageA.Relational

/-! # Static machine import contracts

The declarations in this module are a checked bridge between untrusted static
call-boundary recovery and `MachineImportCallContract`.  A signature describes
one normalized PE import.  A boundary selects a concrete argument count and an
exact direct-import or caller/import-thunk route.  `StaticMachineImportBoundary.valid`
re-decodes the submitted PE spans before exposing a machine-call contract.

Nested-callback protocols use call-site-indexed contracts.  They are valid
boundary contracts, but they remain unavailable through the legacy global
one-contract-per-import projection. -/

inductive StaticMachineCallABI where
  | cdecl
  | stdcall
deriving Repr, DecidableEq

def StaticMachineCallABI.calleeCleanup : StaticMachineCallABI -> Bool
  | .cdecl => false
  | .stdcall => true

def StaticMachineCallABI.preservedRegisters :
    StaticMachineCallABI -> List Reg
  | .cdecl | .stdcall => [.ebp, .ebx, .edi, .esi]

def StaticMachineCallABI.clobberedRegisters :
    StaticMachineCallABI -> List Reg
  | .cdecl | .stdcall => [.eax, .ecx, .edx]

inductive StaticMachineImportArity where
  | fixed (words : Nat)
  | variadic (minimumWords : Nat)
deriving Repr, DecidableEq

def StaticMachineImportArity.minimumWords : StaticMachineImportArity -> Nat
  | .fixed words | .variadic words => words

def StaticMachineImportArity.accepts
    (arity : StaticMachineImportArity) (words : Nat) : Bool :=
  match arity with
  | .fixed expected => words == expected
  | .variadic minimum => minimum <= words

inductive StaticMachineImportCallbackMode where
  | none
  | registration
  | nestedFrames
deriving Repr, DecidableEq

/-- A source-level prototype is deliberately absent.  These are machine-level
facts only. -/
structure StaticMachineImportSignature where
  id : Nat
  imported : ExternalTarget
  abi : StaticMachineCallABI
  arity : StaticMachineImportArity
  resultRegisterRelations : List MachineCallResultRegisterRelation := []
  disposition : MachineCallDisposition := .returns
  memoryEffect : MachineCallMemoryEffect
  memoryFootprints : List MachineCallMemoryFootprint := []
  worldEffect : MachineCallWorldEffect
  callbackMode : StaticMachineImportCallbackMode := .none
deriving Repr, DecidableEq

def staticMachineArgumentOffsets (words : Nat) : List Nat :=
  (List.range words).map (fun index => index * 4)

def StaticMachineImportSignature.contract
    (signature : StaticMachineImportSignature) (words : Nat) :
    MachineImportCallContract := {
  id := signature.id
  imported := signature.imported
  stackArgumentOffsets := staticMachineArgumentOffsets words
  stackResultDelta :=
    if signature.abi.calleeCleanup then words * 4 else 0
  preservedRegisters := signature.abi.preservedRegisters
  clobberedRegisters := signature.abi.clobberedRegisters
  resultRegisterRelations := signature.resultRegisterRelations
  disposition := signature.disposition
  memoryEffect := signature.memoryEffect
  memoryFootprints := signature.memoryFootprints
  worldEffect := signature.worldEffect
}

def StaticMachineImportSignature.callbackShapeValid
    (signature : StaticMachineImportSignature) : Bool :=
  match signature.callbackMode with
  | .none =>
      match signature.worldEffect with
      | .callbackRegistration _ => false
      | _ => true
  | .registration =>
      match signature.worldEffect with
      | .callbackRegistration _ => signature.disposition == .returns
      | _ => false
  | .nestedFrames =>
      signature.disposition == .protocol &&
        signature.memoryEffect == .relationalState &&
        signature.memoryFootprints.isEmpty &&
        signature.worldEffect == .none

/-- Profile validity checks effect and ABI shape at the minimum arity. -/
def StaticMachineImportSignature.shapeValid
    (signature : StaticMachineImportSignature) : Bool :=
  signature.arity.minimumWords <= 256 &&
    signature.callbackShapeValid &&
    (signature.contract signature.arity.minimumWords).shapeValid

def StaticMachineImportSignature.bridgeContract?
    (signature : StaticMachineImportSignature) (words : Nat) :
    Option MachineImportCallContract :=
  if !signature.arity.accepts words then
    none
  else
    let contract := signature.contract words
    if contract.shapeValid then some contract else none

def staticMachineImportSignatureIdsUnique
    (signatures : List StaticMachineImportSignature) : Bool :=
  signatures.all fun signature =>
    (signatures.filter (fun other => other.id == signature.id)).length == 1

def staticMachineImportSignatureTargetsUnique
    (signatures : List StaticMachineImportSignature) : Bool :=
  signatures.all fun signature =>
    (signatures.filter
      (fun other => other.imported == signature.imported)).length == 1

def staticMachineImportTargetsUnique (targets : List ExternalTarget) : Bool :=
  targets.all fun target => (targets.filter (· == target)).length == 1

/-- Reparse the exact PE and require exactly one complete signature for every
requested normalized identity.  Extra imports in the PE are permitted because
reachability chooses the requested subset. -/
def staticMachineImportProfilesValid
    (pe : PE32) (imports : List PEImport) (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature) : Bool :=
  parseImports pe == some imports &&
    staticMachineImportTargetsUnique required &&
    staticMachineImportSignatureIdsUnique signatures &&
    staticMachineImportSignatureTargetsUnique signatures &&
    (signatures.all fun signature =>
      signature.shapeValid && required.contains signature.imported &&
        (imports.any fun imported =>
          signature.imported == normalizeImport imported)) &&
    (required.all fun target =>
      (signatures.filter
        (fun signature => signature.imported == target)).length == 1)

structure StaticMachineImportProfileCertificate
    (pe : PE32) (imports : List PEImport) (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature) : Prop where
  checked : staticMachineImportProfilesValid pe imports required signatures = true

inductive StaticMachineImportBoundaryRoute where
  | direct (span : Span)
  | viaThunk (caller thunk : Span)
  | framedDirectTail (caller entry tail : Span)
  | framedThunkTail (caller entry tail thunk : Span)
  | registerIndirect (span : Span) (dispatchRegister : Reg) (iatRva : Nat)
  | restoredRegisterIndirect
      (seed restore dispatch : Span) (dispatchRegister : Reg)
      (iatRva savedStackOffset : Nat)
deriving Repr, DecidableEq

structure StaticMachineImportBoundary where
  id : Nat
  signatureId : Nat
  instructionRva : Nat
  executionSourceRva : Nat
  continuationRva : Nat
  argumentWords : Nat
  route : StaticMachineImportBoundaryRoute
deriving Repr, DecidableEq

def StaticMachineImportBoundary.sourceSpan
    (boundary : StaticMachineImportBoundary) : Span :=
  match boundary.route with
  | .direct span | .viaThunk span _ | .registerIndirect span _ _ => span
  | .restoredRegisterIndirect _ _ dispatch _ _ _ => dispatch
  | .framedDirectTail caller _ _ | .framedThunkTail caller _ _ _ => caller

/-- The exact span whose decoded behavior emits the external event.  This can
start inside a larger relational region, notably when a register load and its
indirect call share a block with a prologue. -/
def StaticMachineImportBoundary.executionSpan
    (boundary : StaticMachineImportBoundary) : Span :=
  match boundary.route with
  | .direct span | .registerIndirect span _ _ => span
  | .restoredRegisterIndirect _ _ dispatch _ _ _ => dispatch
  | .viaThunk _ thunk | .framedThunkTail _ _ _ thunk => thunk
  | .framedDirectTail _ _ tail => tail

def staticMachineImportCallOutcomeValid
    (target : ExternalTarget) (argumentWords : Nat)
    (continuationRva : Nat) (behavior : SymbolicBehavior) : Bool :=
  match behavior.outcome with
  | some (.externalCall imported arguments continuation) =>
      normalizeImport imported == target && arguments.length == argumentWords &&
        continuation == continuationRva
  | _ => false

def staticMachineImportJumpOutcomeValid
    (target : ExternalTarget) (argumentWords : Nat)
    (behavior : SymbolicBehavior) : Bool :=
  match behavior.outcome with
  | some (.externalJump imported arguments) =>
      normalizeImport imported == target && arguments.length == argumentWords
  | _ => false

def staticMachineImportCallerTargetsThunk
    (behavior : SymbolicBehavior) (thunk : Span) (continuationRva : Nat) : Bool :=
  match behavior.outcome with
  | some (.call target continuation _) =>
      target == thunk.start && continuation == continuationRva
  | _ => false

def staticMachineImportCallerEstablishesFrame
    (behavior : SymbolicBehavior) (entry : Span)
    (continuationRva : Nat) : Bool :=
  match behavior.outcome with
  | some (.call target continuation _) =>
      target == entry.start && continuation == continuationRva
  | _ => false

def staticMachineImportTailTargetsThunk
    (behavior : SymbolicBehavior) (thunk : Span) : Bool :=
  match behavior.outcome with
  | some (.jump target) => target == thunk.start
  | _ => false

def staticMachineImportRegisterTargetValid
    (pe : PE32) (imports : List PEImport)
    (signature : StaticMachineImportSignature)
    (dispatchRegister : Reg) (iatRva : Nat)
    (behavior : SymbolicBehavior) : Bool :=
  pe.imageBase + iatRva < 2^32 &&
    imports.any (fun imported =>
      imported.iatRva == iatRva &&
        normalizeImport imported == signature.imported) &&
    match behavior.outcome with
    | some (.indirectCall target _ _) =>
        target == .read32 (.constant (pe.imageBase + iatRva)) &&
          (target == .inputReg dispatchRegister ||
            target == behavior.registers.get dispatchRegister)
    | _ => false

def lastWriteValue? (writes : List (Expr × Expr)) (address : Expr) :
    Option Expr :=
  (writes.reverse.find? fun write => write.1 == address).map (·.2)

def staticMachineImportRestoreReaches
    (behavior : SymbolicBehavior) (dispatch : Span) : Bool :=
  match behavior.outcome with
  | some (.jump target) => target == dispatch.start
  | some (.branch _ taken fallthrough) =>
      taken == dispatch.start || fallthrough == dispatch.start
  | none => false
  | _ => false

def staticMachineImportRestoredTargetValid
    (dispatchRegister : Reg) (behavior : SymbolicBehavior) : Bool :=
  match behavior.outcome with
  | some (.indirectCall target _ _) =>
      target == .inputReg dispatchRegister &&
        behavior.registers.get dispatchRegister == .inputReg dispatchRegister
  | _ => false

def staticMachineImportRestoredRegisterRouteValid
    (pe : PE32) (imports : List PEImport)
    (signature : StaticMachineImportSignature)
    (contract : MachineImportCallContract)
    (continuationRva : Nat) (argumentWords : Nat)
    (seed restore dispatch : Span) (dispatchRegister : Reg)
    (iatRva savedStackOffset : Nat) : Bool :=
  seed.size > 0 && restore.size > 0 && dispatch.size > 0 &&
    seed.start + seed.size == restore.start &&
    contract.stackResultDelta <= savedStackOffset &&
    argumentWords * 4 <= savedStackOffset &&
    (contract.memoryEffect == .none ||
      contract.memoryEffect == .readOnly) &&
    match regionBehaviorWithImports pe imports seed,
        regionBehaviorWithImports pe imports restore,
        regionBehaviorWithImports pe imports dispatch with
    | some seedBehavior, some restoreBehavior, some dispatchBehavior =>
        let iatValue : Expr :=
          .read32 (.constant (pe.imageBase + iatRva))
        let savedAddress : Expr :=
          (Expr.inputReg .esp).offset savedStackOffset
        let restoredOffset := savedStackOffset - contract.stackResultDelta
        staticMachineImportRegisterTargetValid pe imports signature
            dispatchRegister iatRva seedBehavior &&
          lastWriteValue? seedBehavior.writes savedAddress == some iatValue &&
          (match externalizeRegisterImportCall contract dispatchRegister
              seedBehavior with
          | some externalized =>
              staticMachineImportCallOutcomeValid signature.imported
                argumentWords restore.start externalized
          | none => false) &&
          restoreBehavior.registers.get dispatchRegister ==
            .read32 ((Expr.inputReg .esp).offset restoredOffset) &&
          staticMachineImportRestoreReaches restoreBehavior dispatch &&
          staticMachineImportRestoredTargetValid dispatchRegister
            dispatchBehavior &&
          (match externalizeRegisterImportCall contract dispatchRegister
              dispatchBehavior with
          | some externalized =>
              staticMachineImportCallOutcomeValid signature.imported
                argumentWords continuationRva externalized
          | none => false)
    | _, _, _ => false

def StaticMachineImportBoundary.routeValid
    (pe : PE32) (imports : List PEImport)
    (signature : StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary)
    (contract : MachineImportCallContract) : Bool :=
  let source := boundary.sourceSpan
  source.size > 0 && source.start <= boundary.instructionRva &&
    boundary.instructionRva < source.start + source.size &&
    match boundary.route with
    | .direct span =>
        boundary.executionSourceRva == span.start &&
        match regionBehaviorWithMachineCallContracts pe imports [contract] span with
        | some behavior =>
            staticMachineImportCallOutcomeValid signature.imported
              boundary.argumentWords boundary.continuationRva behavior
        | none => false
    | .viaThunk caller thunk =>
        caller.size > 0 && thunk.size > 0 &&
          boundary.executionSourceRva == thunk.start &&
          match regionBehaviorWithImports pe imports caller,
              regionBehaviorWithMachineCallContracts pe imports [contract] thunk with
          | some callerBehavior, some thunkBehavior =>
              staticMachineImportCallerTargetsThunk callerBehavior thunk
                  boundary.continuationRva &&
                staticMachineImportJumpOutcomeValid signature.imported
                  boundary.argumentWords thunkBehavior
          | _, _ => false
    | .framedDirectTail caller entry tail =>
        caller.size > 0 && entry.size > 0 && tail.size > 0 &&
          boundary.executionSourceRva == tail.start &&
          match regionBehaviorWithImports pe imports caller,
              regionBehaviorWithMachineCallContracts pe imports [contract] tail with
          | some callerBehavior, some tailBehavior =>
              staticMachineImportCallerEstablishesFrame callerBehavior entry
                  boundary.continuationRva &&
                staticMachineImportJumpOutcomeValid signature.imported
                  boundary.argumentWords tailBehavior
          | _, _ => false
    | .framedThunkTail caller entry tail thunk =>
        caller.size > 0 && entry.size > 0 && tail.size > 0 && thunk.size > 0 &&
          boundary.executionSourceRva == thunk.start &&
          match regionBehaviorWithImports pe imports caller,
              regionBehaviorWithImports pe imports tail,
              regionBehaviorWithMachineCallContracts pe imports [contract] thunk with
          | some callerBehavior, some tailBehavior, some thunkBehavior =>
              staticMachineImportCallerEstablishesFrame callerBehavior entry
                  boundary.continuationRva &&
                staticMachineImportTailTargetsThunk tailBehavior thunk &&
                staticMachineImportJumpOutcomeValid signature.imported
                  boundary.argumentWords thunkBehavior
          | _, _, _ => false
    | .registerIndirect span dispatchRegister iatRva =>
        boundary.executionSourceRva == span.start &&
        match regionBehaviorWithImports pe imports span with
        | none => false
        | some behavior =>
            staticMachineImportRegisterTargetValid pe imports signature
                dispatchRegister iatRva behavior &&
              match externalizeRegisterImportCall contract dispatchRegister behavior with
              | some externalized =>
                  staticMachineImportCallOutcomeValid signature.imported
                    boundary.argumentWords boundary.continuationRva externalized
              | none => false
    | .restoredRegisterIndirect seed restore dispatch dispatchRegister iatRva
        savedStackOffset =>
        boundary.executionSourceRva == dispatch.start &&
          staticMachineImportRestoredRegisterRouteValid pe imports signature
            contract boundary.continuationRva boundary.argumentWords seed restore
            dispatch dispatchRegister iatRva savedStackOffset

def StaticMachineImportBoundary.valid
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary) : Bool :=
  match signatures.find? (fun signature => signature.id == boundary.signatureId) with
  | none => false
  | some signature =>
      match signature.bridgeContract? boundary.argumentWords with
      | none => false
      | some contract => boundary.routeValid pe imports signature contract

def staticMachineImportBoundariesValid
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) : Bool :=
  boundaries.all fun boundary =>
    (boundaries.filter (fun other => other.id == boundary.id)).length == 1 &&
      boundary.valid pe imports signatures

def staticMachineImportBoundaryCoverageValid
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) : Bool :=
  required.all fun target =>
    match signatures.find? (fun signature => signature.imported == target) with
    | none => false
    | some signature =>
        boundaries.any fun boundary => boundary.signatureId == signature.id

structure StaticMachineImportBoundaryCertificate
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) : Prop where
  checked :
    staticMachineImportBoundariesValid pe imports signatures boundaries = true

def StaticMachineImportBoundary.contract?
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary) : Option MachineImportCallContract := do
  let signature <- signatures.find? (fun item => item.id == boundary.signatureId)
  signature.bridgeContract? boundary.argumentWords

/-- One call-site-specific contract.  Contract identifiers are boundary IDs,
not import-signature IDs, so two variadic calls to the same import may carry
different checked argument inventories without becoming ambiguous. -/
structure StaticMachineImportResolvedBoundary where
  boundary : StaticMachineImportBoundary
  contract : MachineImportCallContract
deriving Repr, DecidableEq

def StaticMachineImportBoundary.resolveContract?
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary) :
    Option StaticMachineImportResolvedBoundary := do
  let contract <- boundary.contract? signatures
  pure { boundary, contract := { contract with id := boundary.id } }

def staticMachineImportBoundaryContracts?
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) :
    Option (List StaticMachineImportResolvedBoundary) :=
  boundaries.mapM (·.resolveContract? signatures)

/-- Exact-route and call-site resolution evidence remain in one package.  This
is the migration source for decoded-original execution; it does not impose a
one-contract-per-import uniqueness condition. -/
structure CheckedStaticMachineImportBoundaryContracts
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) where
  routes : StaticMachineImportBoundaryCertificate pe imports signatures boundaries
  inventory : List StaticMachineImportResolvedBoundary
  resolved : staticMachineImportBoundaryContracts? signatures boundaries =
    some inventory

/-- An exact submitted boundary that is permitted to terminate execution.
The binding remains data-only: `valid` resolves it uniquely through the checked
boundary inventory and static context, then rechecks its exact decoded route. -/
structure StaticMachineImportTerminalBoundaryBinding where
  boundary : StaticMachineImportBoundary
deriving Repr, DecidableEq

def StaticMachineImportTerminalBoundaryBinding.valid
    (context : StaticProofContext)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (binding : StaticMachineImportTerminalBoundaryBinding) : Bool :=
  let boundaryMatches := boundaries.filter fun boundary =>
    boundary.id == binding.boundary.id
  let signatureMatches := signatures.filter fun signature =>
    signature.id == binding.boundary.signatureId
  let inventoryMatches := inventory.filter fun resolved =>
    resolved.boundary.id == binding.boundary.id
  let contextContractMatches := context.machineImportCallContracts.filter fun
    contract => contract.id == binding.boundary.id
  boundaryMatches.length == 1 && signatureMatches.length == 1 &&
    inventoryMatches.length == 1 && contextContractMatches.length == 1 &&
    match boundaryMatches.head?, inventoryMatches.head?,
        contextContractMatches.head? with
    | some boundary, some resolved, some contextContract =>
        boundary == binding.boundary && resolved.boundary == binding.boundary &&
          binding.boundary.resolveContract? signatures == some resolved &&
          resolved.contract == contextContract &&
          binding.boundary.valid context.originalPe context.originalImports
            signatures &&
          contextContract.disposition == .terminates
    | _, _, _ => false

/-- A target-ID projection for one exact machine-import boundary.  RVAs remain
the authority: `StaticMachineImportBoundarySiteBinding.valid` resolves both
submitted IDs through the checked original code map before exposing an
`ExternalCallSiteContract`. -/
structure StaticMachineImportBoundarySiteBinding where
  boundaryId : Nat
  sourceTargetId : Nat
  continuationTargetId : Nat
  boundaryInvariant : StateInvariant
  targetInvariant : StateInvariant
deriving Repr, DecidableEq

def StaticMachineImportBoundarySiteBinding.site
    (binding : StaticMachineImportBoundarySiteBinding) :
    ExternalCallSiteContract := {
  id := binding.boundaryId
  sourceTargetId := binding.sourceTargetId
  continuationTargetId := binding.continuationTargetId
  machineContractId := binding.boundaryId
  boundaryInvariant := binding.boundaryInvariant
  targetInvariant := binding.targetInvariant
}

def StaticMachineImportBoundarySiteBinding.valid
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (binding : StaticMachineImportBoundarySiteBinding) : Bool :=
  match boundaries.find? fun boundary => boundary.id == binding.boundaryId,
      inventory.find? fun resolved => resolved.boundary.id == binding.boundaryId,
      context.codeMap.get? binding.sourceTargetId with
  | some boundary, some resolved, some sourceTarget =>
      context.originalPe.imageBase + boundary.executionSourceRva < 2^32 &&
        context.originalPe.imageBase + boundary.continuationRva < 2^32 &&
        resolved.boundary == boundary &&
        (machineImportCallContractById? context binding.boundaryId ==
          some resolved.contract) &&
        sourceTarget.id == binding.sourceTargetId &&
        (match regions[sourceTarget.regionIndex]? with
        | none => false
        | some sourceRegion =>
            sourceRegion.id == sourceTarget.regionIndex &&
            sourceRegion.original.start == sourceTarget.originalRva &&
            sourceRegion.original.start <= boundary.executionSpan.start &&
            boundary.executionSpan.start < sourceRegion.original.stop) &&
        (context.codeMap.resolveRawEip false context.originalPe.imageBase
          (BitVec.ofNat 32
            (context.originalPe.imageBase + boundary.continuationRva)) ==
          some binding.continuationTargetId)
  | _, _, _ => false

/-- Indexed form of `valid`.  The semantic check is identical, but generated
large-program proofs avoid repeatedly reducing an appended list of every
decoded region. -/
def StaticMachineImportBoundarySiteBinding.validIndexed
    (context : StaticProofContext)
    (regions : FiniteIndex RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (binding : StaticMachineImportBoundarySiteBinding) : Bool :=
  match boundaries.find? fun boundary => boundary.id == binding.boundaryId,
      inventory.find? fun resolved => resolved.boundary.id == binding.boundaryId,
      context.codeMap.get? binding.sourceTargetId with
  | some boundary, some resolved, some sourceTarget =>
      context.originalPe.imageBase + boundary.executionSourceRva < 2^32 &&
        context.originalPe.imageBase + boundary.continuationRva < 2^32 &&
        resolved.boundary == boundary &&
        (machineImportCallContractById? context binding.boundaryId ==
          some resolved.contract) &&
        sourceTarget.id == binding.sourceTargetId &&
        (match regions.get? sourceTarget.regionIndex with
        | none => false
        | some sourceRegion =>
            sourceRegion.id == sourceTarget.regionIndex &&
            sourceRegion.original.start == sourceTarget.originalRva &&
            sourceRegion.original.start <= boundary.executionSpan.start &&
            boundary.executionSpan.start < sourceRegion.original.stop) &&
        (context.codeMap.resolveRawEip false context.originalPe.imageBase
          (BitVec.ofNat 32
            (context.originalPe.imageBase + boundary.continuationRva)) ==
          some binding.continuationTargetId)
  | _, _, _ => false

theorem StaticMachineImportBoundarySiteBinding.validIndexed_eq_valid
    (context : StaticProofContext)
    (regions : FiniteIndex RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (binding : StaticMachineImportBoundarySiteBinding)
    (sizesSound : regions.sizesSound = true) :
    binding.validIndexed context regions boundaries inventory =
      binding.valid context regions.toList boundaries inventory := by
  simp only [StaticMachineImportBoundarySiteBinding.validIndexed,
    StaticMachineImportBoundarySiteBinding.valid,
    FiniteIndex.get?_eq_toList_get? regions _ sizesSound]

def staticMachineImportBoundarySiteBindingsValid
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (bindings : List StaticMachineImportBoundarySiteBinding) : Bool :=
  (bindings.all fun binding =>
      (bindings.filter
        (fun other => other.boundaryId == binding.boundaryId)).length == 1 &&
      binding.valid context regions boundaries inventory) &&
    (boundaries.all fun boundary =>
      (bindings.filter
        (fun binding => binding.boundaryId == boundary.id)).length == 1)

def staticMachineImportBoundarySiteBindingsIndexedValid
    (context : StaticProofContext)
    (regions : FiniteIndex RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (bindings : List StaticMachineImportBoundarySiteBinding) : Bool :=
  (bindings.all fun binding =>
      (bindings.filter
        (fun other => other.boundaryId == binding.boundaryId)).length == 1 &&
      binding.validIndexed context regions boundaries inventory) &&
    (boundaries.all fun boundary =>
      (bindings.filter
        (fun binding => binding.boundaryId == boundary.id)).length == 1)

theorem staticMachineImportBoundarySiteBindingsIndexedValid_sound
    (context : StaticProofContext)
    (regions : FiniteIndex RegionRelation)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (bindings : List StaticMachineImportBoundarySiteBinding)
    (sizesSound : regions.sizesSound = true)
    (checked : staticMachineImportBoundarySiteBindingsIndexedValid context
      regions boundaries inventory bindings = true) :
    staticMachineImportBoundarySiteBindingsValid context regions.toList
      boundaries inventory bindings = true := by
  simp only [staticMachineImportBoundarySiteBindingsIndexedValid,
    staticMachineImportBoundarySiteBindingsValid, Bool.and_eq_true,
    List.all_eq_true] at checked ⊢
  refine ⟨?_, checked.2⟩
  intro binding member
  have row := checked.1 binding member
  refine ⟨row.1, ?_⟩
  rw [StaticMachineImportBoundarySiteBinding.validIndexed_eq_valid
    context regions boundaries inventory binding sizesSound] at row
  exact row.2

def staticMachineImportBoundaryExternalCallSites
    (bindings : List StaticMachineImportBoundarySiteBinding) :
    List ExternalCallSiteContract :=
  bindings.map (·.site)

/-- The old decoded context can consume one contract per import only when all
signatures are fixed and synchronously bridgeable.  Variadic and nested-frame
profiles return `none`; callers must use boundary-indexed contracts instead. -/
def staticMachineImportGlobalContracts?
    (signatures : List StaticMachineImportSignature) :
    Option (List MachineImportCallContract) :=
  signatures.mapM fun signature =>
    if signature.callbackMode == .nestedFrames ||
        signature.disposition == .protocol then
      none
    else
      match signature.arity with
      | .fixed words => signature.bridgeContract? words
      | .variadic _ => none

/-- A non-optional global contract list is exposed only through this checked
package.  The equality prevents a generated consumer from substituting a
default list when a variadic or nested-frame signature cannot be represented
by the legacy one-contract-per-import context. -/
structure StaticMachineImportGlobalContractCertificate
    (signatures : List StaticMachineImportSignature) where
  contracts : List MachineImportCallContract
  resolved : staticMachineImportGlobalContracts? signatures = some contracts

/-- The consumer-facing global package couples resolution to the checked exact
PE profile.  A generated list cannot be detached from the proof that the
signature inventory covers every requested normalized import exactly once. -/
structure CheckedStaticMachineImportGlobalProfile
    (pe : PE32) (imports : List PEImport) (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature) where
  profile : StaticMachineImportProfileCertificate pe imports required signatures
  global : StaticMachineImportGlobalContractCertificate signatures

theorem StaticMachineImportBoundary.valid_has_contract
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary)
    (checked : boundary.valid pe imports signatures = true) :
    exists signature contract,
      signatures.find? (fun item => item.id == boundary.signatureId) =
        some signature /\
      signature.bridgeContract? boundary.argumentWords = some contract /\
      boundary.routeValid pe imports signature contract = true := by
  unfold StaticMachineImportBoundary.valid at checked
  split at checked <;> rename_i found
  · simp at checked
  · split at checked <;> rename_i contractFound
    · simp at checked
    · exact ⟨_, _, found, contractFound, checked⟩

#print axioms StaticMachineImportBoundary.valid_has_contract

end StageA.Relational.StaticMachineImportContracts
