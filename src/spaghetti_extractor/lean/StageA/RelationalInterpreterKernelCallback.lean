import StageA.RelationalInterpreterKernel
import StageA.RelationalLinkedFrames
import StageA.RelationalCallbacks

namespace StageA.Relational.InterpreterKernelCallback

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

/-! Checked machine-level ABI contracts for indirect calls made by a compiled
Stage B interpreter kernel.  Static inventories are reflected Booleans over
exact PE bytes.  Dynamic target provenance and callback behavior remain
propositions and therefore cannot be supplied by Python status fields. -/

inductive CDeclReturnKind where
  | void
  | wordInEax
deriving Repr, DecidableEq

structure CDeclMachineABI where
  argumentCount : Nat
  argumentOffsets : List Nat
  callerStackDelta : Nat
  preservedRegisters : List Reg
  returnKind : CDeclReturnKind
deriving Repr, DecidableEq

def cdeclPreservedRegisters : List Reg := [.ebx, .esi, .edi, .ebp]

def CDeclMachineABI.checked (abi : CDeclMachineABI) : Bool :=
  abi.argumentCount <= 64 &&
    abi.argumentOffsets ==
      (List.range abi.argumentCount).map (fun index => index * 4) &&
    abi.callerStackDelta == 0 &&
    abi.preservedRegisters == cdeclPreservedRegisters

def CDeclMachineABI.arguments (abi : CDeclMachineABI)
    (state : MachineState) : List Word :=
  abi.argumentOffsets.map fun offset =>
    Memory.read32 state.memory
      (state.registers.esp + BitVec.ofNat 32 offset)

structure CallbackTargetEntry where
  id : Nat
  entry : KernelInstruction
deriving Repr, DecidableEq

def CallbackTargetEntry.address (pe : PE32)
    (target : CallbackTargetEntry) : Word :=
  BitVec.ofNat 32 (pe.imageBase + target.entry.rva)

def CallbackTargetEntry.checked (pe : PE32) (imports : List PEImport)
    (target : CallbackTargetEntry) : Bool :=
  target.entry.checked pe imports

structure CallbackTargetSet where
  entries : List CallbackTargetEntry
deriving Repr, DecidableEq

def CallbackTargetSet.checked (targets : CallbackTargetSet)
    (pe : PE32) (imports : List PEImport) : Bool :=
  !targets.entries.isEmpty &&
    decide (targets.entries.map (·.id)).Nodup &&
    decide (targets.entries.map (·.entry.rva)).Nodup &&
    targets.entries.all (·.checked pe imports)

def CallbackTargetSet.contains (targets : CallbackTargetSet)
    (pe : PE32) (target : Word) : Bool :=
  targets.entries.any fun entry => entry.address pe == target

def evalAddressing (state : MachineState) (addressing : Addressing) : Word :=
  let base := addressing.base.map state.registers.get
    |>.getD (BitVec.ofNat 32 0)
  let index := addressing.index.map state.registers.get
    |>.getD (BitVec.ofNat 32 0)
  let index := if addressing.scaleShift == 0 then index
    else index.shiftLeft addressing.scaleShift
  base + index + BitVec.ofNat 32 addressing.displacement

def evalOperand32 (state : MachineState) : Operand32 -> Word
  | .register register => state.registers.get register
  | .memory addressing => Memory.read32 state.memory (evalAddressing state addressing)
  | .immediate value => BitVec.ofNat 32 value

structure KernelIndirectCallbackSite where
  id : Nat
  instruction : KernelInstruction
  continuationRva : Nat
  targetOperand : Operand32
  abi : CDeclMachineABI
  targets : CallbackTargetSet
deriving Repr, DecidableEq

def KernelIndirectCallbackSite.decodedExact (site : KernelIndirectCallbackSite)
    (pe : PE32) : Bool :=
  match site.instruction.decode? pe with
  | some decoded =>
      decoded.instruction == .callIndirect site.targetOperand &&
        decoded.size == site.instruction.bytes.length &&
        site.continuationRva == site.instruction.rva + decoded.size
  | none => false

def KernelIndirectCallbackSite.checked (site : KernelIndirectCallbackSite)
    (pe : PE32) (imports : List PEImport) : Bool :=
  site.decodedExact pe && site.instruction.checked pe imports &&
    site.abi.checked && site.targets.checked pe imports

def KernelIndirectCallbackSite.targetWord (site : KernelIndirectCallbackSite)
    (state : MachineState) : Word :=
  evalOperand32 state site.targetOperand

def KernelIndirectCallbackSite.targetAllowed
    (site : KernelIndirectCallbackSite) (pe : PE32)
    (state : MachineState) : Prop :=
  site.targets.contains pe (site.targetWord state) = true

def callbackSitesContainRva
    (sites : List KernelIndirectCallbackSite) (rva : Nat) : Bool :=
  sites.any fun site => site.instruction.rva == rva

structure KernelCallbackInventory where
  sites : List KernelIndirectCallbackSite
deriving Repr, DecidableEq

def compiledKernelProgramContainsInstructionRva
    (program : CompiledKernelProgram) (rva : Nat) : Bool :=
  program.functions.any fun function =>
    function.blocks.any fun block =>
      block.instructions.any fun instruction => instruction.rva == rva

/-- Coverage is derived from exact decoded instructions in the rooted compiled
kernel graph.  An omitted or targetless indirect call makes this checker
false. -/
def KernelCallbackInventory.coversProgram (inventory : KernelCallbackInventory)
    (program : CompiledKernelProgram) (pe : PE32) : Bool :=
  program.functions.all fun function =>
    function.blocks.all fun block =>
      block.instructions.all fun instruction =>
        match instruction.decode? pe with
        | none => false
        | some decoded =>
            match decoded.instruction with
            | .callIndirect _ =>
                callbackSitesContainRva inventory.sites instruction.rva
            | _ => true

def KernelCallbackInventory.checked (inventory : KernelCallbackInventory)
    (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) : Bool :=
  decide (inventory.sites.map (·.id)).Nodup &&
    decide (inventory.sites.map (·.instruction.rva)).Nodup &&
    inventory.sites.all (·.checked pe imports) &&
    inventory.sites.all (fun site =>
      compiledKernelProgramContainsInstructionRva program site.instruction.rva) &&
    inventory.coversProgram program pe

/-- Concrete execution record at an indirect cdecl boundary.  `calleeEntry`
is the state after the hardware return-address push.  `returned` is the state
after the callee's `ret`, at the caller continuation. -/
structure KernelCallbackRun where
  target : Word
  caller : MachineState
  calleeEntry : MachineState
  returned : MachineState
  continuationRva : Nat
  arguments : List Word
  result : Option Word

def CDeclEntryHolds (pe : PE32) (site : KernelIndirectCallbackSite)
    (run : KernelCallbackRun) : Prop :=
  run.arguments = site.abi.arguments run.caller ∧
    run.target = site.targetWord run.caller ∧
    run.calleeEntry.registers.esp =
    run.caller.registers.esp - BitVec.ofNat 32 4 ∧
    Memory.read32 run.calleeEntry.memory run.calleeEntry.registers.esp =
      BitVec.ofNat 32 (pe.imageBase + site.continuationRva) ∧
    (∀ register, register != .esp ->
      run.calleeEntry.registers.get register =
        run.caller.registers.get register) ∧
    (∀ offset ∈ site.abi.argumentOffsets,
      Memory.read32 run.calleeEntry.memory
          (run.calleeEntry.registers.esp + BitVec.ofNat 32 (4 + offset)) =
        Memory.read32 run.caller.memory
          (run.caller.registers.esp + BitVec.ofNat 32 offset))

def CDeclReturnHolds (site : KernelIndirectCallbackSite)
    (run : KernelCallbackRun) : Prop :=
  run.continuationRva = site.continuationRva ∧
    run.returned.registers.esp = run.caller.registers.esp +
      BitVec.ofNat 32 site.abi.callerStackDelta ∧
    (∀ register ∈ site.abi.preservedRegisters,
      run.returned.registers.get register = run.caller.registers.get register) ∧
    match site.abi.returnKind with
    | .void => run.result = none
    | .wordInEax => run.result = some run.returned.registers.eax

/-- The callback may update candidate memory, but it must preserve the active
and suspended relational call frames.  This is deliberately a proposition:
the callback implementation or its environment contract must prove it. -/
def NestedFrameRelationPreserved (context : StaticProofContext)
    (original : MachineState) (before after : MachineState) : Prop :=
  ∀ frames continuations active links,
    RelationalLinkedRuntimeCallStackHolds context original before
        frames continuations active links ->
      RelationalLinkedRuntimeCallStackHolds context original after
        frames continuations active links

structure KernelIndirectCallbackRefinement
    (context : StaticProofContext)
    (site : KernelIndirectCallbackSite) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (sourceInvariant : MachineState -> Prop)
    (runs : KernelCallbackRun -> Prop) : Prop where
  staticSite : site.checked pe imports = true
  listedByProgram : program.functions.any fun function =>
    function.blocks.any fun block =>
      block.instructions.any fun instruction =>
        instruction.rva == site.instruction.rva
  targetMembership : ∀ state,
    sourceInvariant state -> site.targetAllowed pe state
  entryBoundary : ∀ run,
    runs run -> sourceInvariant run.caller -> CDeclEntryHolds pe site run
  returnBoundary : ∀ run,
    runs run -> sourceInvariant run.caller -> CDeclReturnHolds site run
  nestedFrames : ∀ run original,
    runs run -> sourceInvariant run.caller ->
      NestedFrameRelationPreserved context original run.caller run.returned

structure CompiledKernelCallbacksRefine
    (context : StaticProofContext)
    (inventory : KernelCallbackInventory) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite -> KernelCallbackRun -> Prop) : Prop where
  exactCoverage : inventory.checked program pe imports = true
  siteRefinement : ∀ site ∈ inventory.sites,
    KernelIndirectCallbackRefinement context site program pe imports
      (sourceInvariant site) (runs site)

theorem KernelIndirectCallbackRefinement.sound
    {site : KernelIndirectCallbackSite} {program : CompiledKernelProgram}
    {context : StaticProofContext}
    {pe : PE32} {imports : List PEImport}
    {sourceInvariant : MachineState -> Prop}
    {runs : KernelCallbackRun -> Prop}
    (certificate : KernelIndirectCallbackRefinement context site program pe imports
      sourceInvariant runs)
    (run : KernelCallbackRun) (original : MachineState)
    (executed : runs run) (source : sourceInvariant run.caller) :
    site.targetAllowed pe run.caller ∧ CDeclEntryHolds pe site run ∧
      CDeclReturnHolds site run ∧
      NestedFrameRelationPreserved context original
        run.caller run.returned := by
  exact ⟨certificate.targetMembership run.caller source,
    certificate.entryBoundary run executed source,
    certificate.returnBoundary run executed source,
    certificate.nestedFrames run original executed source⟩

/-! Relocation-backed target provenance.  The submitted relocation list is
not trusted: `checked` re-parses it from the exact PE and verifies both the
on-disk pointer word and the unique HIGHLOW relocation at each cell. -/

def CallbackTargetSet.findId? (targets : CallbackTargetSet)
    (targetId : Nat) : Option CallbackTargetEntry :=
  targets.entries.find? fun target => target.id == targetId

structure RelocationBackedCallbackTargetCell where
  id : Nat
  cellRva : Nat
  targetId : Nat
deriving Repr, DecidableEq

def callbackRelocationCount (relocations : List BaseRelocation)
    (rva : Nat) : Nat :=
  (relocations.filter fun relocation =>
    relocation.rva == rva && relocation.kind == 3).length

def RelocationBackedCallbackTargetCell.checked
    (cell : RelocationBackedCallbackTargetCell) (pe : PE32)
    (relocations : List BaseRelocation) (targets : CallbackTargetSet) : Bool :=
  cell.cellRva % 4 == 0 && callbackRelocationCount relocations cell.cellRva == 1 &&
    match targets.findId? cell.targetId with
    | none => false
    | some target =>
        readRvaU32 pe cell.cellRva == some (pe.imageBase + target.entry.rva)

def RelocationBackedCallbackTargetCell.address
    (cell : RelocationBackedCallbackTargetCell) (pe : PE32) : Word :=
  BitVec.ofNat 32 (pe.imageBase + cell.cellRva)

def RelocationBackedCallbackTargetCell.Holds
    (cell : RelocationBackedCallbackTargetCell) (pe : PE32)
    (target : CallbackTargetEntry) (state : MachineState) : Prop :=
  cell.targetId = target.id ∧
    Memory.read32 state.memory (cell.address pe) = target.address pe

structure RelocationBackedCallbackTargetInventory where
  cells : List RelocationBackedCallbackTargetCell
deriving Repr, DecidableEq

def RelocationBackedCallbackTargetInventory.covers
    (inventory : RelocationBackedCallbackTargetInventory)
    (targets : CallbackTargetSet) : Bool :=
  targets.entries.all fun target =>
    inventory.cells.any fun cell => cell.targetId == target.id

def RelocationBackedCallbackTargetInventory.checked
    (inventory : RelocationBackedCallbackTargetInventory)
    (pe : PE32) (targets : CallbackTargetSet) : Bool :=
  !inventory.cells.isEmpty &&
    decide (inventory.cells.map (·.id)).Nodup &&
    decide (inventory.cells.map (·.cellRva)).Nodup &&
    match parseRelocations pe with
    | none => false
    | some relocations =>
        inventory.cells.all (fun cell => cell.checked pe relocations targets) &&
          inventory.covers targets

def RelocationBackedCallbackTargetInventory.CellHoldsFor
    (inventory : RelocationBackedCallbackTargetInventory)
    (pe : PE32) (target : CallbackTargetEntry)
    (state : MachineState) : Prop :=
  ∃ cell ∈ inventory.cells, cell.Holds pe target state

/-! Exact cdecl observations and nested-frame preservation.  The mixed stack
is authoritative here: it may contain any nesting of internal return frames
and suspended external callback frames. -/

def ExactCDeclCallHolds (pe : PE32) (site : KernelIndirectCallbackSite)
    (run : KernelCallbackRun) : Prop :=
  CDeclEntryHolds pe site run ∧ CDeclReturnHolds site run

def NestedMixedFrameRelationPreserved (context : StaticProofContext)
    (world : RelationalWorld) (original : MachineState)
    (before after : MachineState) : Prop :=
  ∀ frames continuations offsets,
    RelationalMixedRuntimeStackHolds context world original before
        frames continuations offsets ->
      RelationalMixedRuntimeStackHolds context world original after
        frames continuations offsets

structure KernelCallbackExecutionTrace where
  run : KernelCallbackRun
  eventIndex : Nat
  afterEventIndex : Nat
  beforeEvents : List NativeExternalEvent
  emittedEvents : List NativeExternalEvent

def callbackNativeFrame (pe : PE32) (site : KernelIndirectCallbackSite) :
    NativeCallFrame := {
  continuationRva := site.continuationRva
  returnAddress := BitVec.ofNat 32 (pe.imageBase + site.continuationRva)
}

/-- Execute the selected target from its exact PE entry until it returns to
the checked caller continuation.  The sentinel native frame makes the exact
machine semantics validate the concrete return address instead of discarding
it at a top-level `ret`. -/
def ExactCallbackTargetExecution (site : KernelIndirectCallbackSite)
    (target : CallbackTargetEntry) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (trace : KernelCallbackExecutionTrace) :
    Prop :=
  trace.afterEventIndex = trace.eventIndex + trace.emittedEvents.length ∧
    NativeSteps pe imports environment
      (.running target.entry.rva 0 trace.run.calleeEntry
        [callbackNativeFrame pe site] trace.eventIndex trace.beforeEvents)
      (.running site.continuationRva 0 trace.run.returned []
        trace.afterEventIndex (trace.beforeEvents ++ trace.emittedEvents))

/-- A target contract relates exact machine-level arguments, the exact return
state, and all external events emitted while the target executes.  Stage A's
operation proof must supply this proposition; the static callback inventory
cannot manufacture environment refinement. -/
structure KernelCallbackTargetContract where
  effect : CallbackTargetEntry -> List Word -> Option Word ->
    MachineState -> MachineState -> List NativeExternalEvent -> Prop

structure KernelIndirectCallbackExecutionRefinement
    (context : StaticProofContext) (world : RelationalWorld)
    (site : KernelIndirectCallbackSite)
    (cells : RelocationBackedCallbackTargetInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (contract : KernelCallbackTargetContract)
    (sourceInvariant : MachineState -> Prop)
    (runs : KernelCallbackExecutionTrace -> Prop) : Prop where
  staticSite : site.checked pe imports = true
  listedByProgram : compiledKernelProgramContainsInstructionRva program
    site.instruction.rva = true
  exactTargetCells : cells.checked pe site.targets = true
  runForSource : ∀ state, sourceInvariant state ->
    ∃ trace, runs trace ∧ trace.run.caller = state
  runRefines : ∀ trace,
    runs trace -> sourceInvariant trace.run.caller ->
      ∃ target ∈ site.targets.entries,
        trace.run.target = target.address pe ∧
        site.targetWord trace.run.caller = target.address pe ∧
        cells.CellHoldsFor pe target trace.run.caller ∧
        ExactCDeclCallHolds pe site trace.run ∧
        ExactCallbackTargetExecution site target pe imports environment trace ∧
        contract.effect target trace.run.arguments trace.run.result
          trace.run.calleeEntry trace.run.returned trace.emittedEvents ∧
        (∀ original,
          NestedFrameRelationPreserved context original trace.run.caller
            trace.run.returned) ∧
        (∀ original,
          NestedMixedFrameRelationPreserved context world original
            trace.run.caller trace.run.returned)

structure CompiledKernelCallbackExecutionsRefine
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelCallbackInventory) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop) : Prop where
  exactCoverage : inventory.checked program pe imports = true
  siteRefinement : ∀ site ∈ inventory.sites,
    KernelIndirectCallbackExecutionRefinement context world site (cells site)
      program pe imports environment (contracts site) (sourceInvariant site)
      (runs site)

/-- Entry-only refinement used by callback-aware execution.  Target completion
is intentionally separated because a generated bridge target may itself cross
an external ret trampoline. -/
structure KernelIndirectCallbackEntryRefinement
    (context : StaticProofContext) (world : RelationalWorld)
    (site : KernelIndirectCallbackSite)
    (cells : RelocationBackedCallbackTargetInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (contract : KernelCallbackTargetContract)
    (sourceInvariant : MachineState -> Prop)
    (runs : KernelCallbackExecutionTrace -> Prop) : Prop where
  staticSite : site.checked pe imports = true
  listedByProgram : compiledKernelProgramContainsInstructionRva program
    site.instruction.rva = true
  exactTargetCells : cells.checked pe site.targets = true
  runForSource : ∀ state, sourceInvariant state ->
    ∃ trace, runs trace ∧ trace.run.caller = state
  runRefines : ∀ trace,
    runs trace -> sourceInvariant trace.run.caller ->
      ∃ target ∈ site.targets.entries,
        trace.run.target = target.address pe ∧
        site.targetWord trace.run.caller = target.address pe ∧
        cells.CellHoldsFor pe target trace.run.caller ∧
        ExactCDeclCallHolds pe site trace.run ∧
        contract.effect target trace.run.arguments trace.run.result
          trace.run.calleeEntry trace.run.returned trace.emittedEvents ∧
        (∀ original,
          NestedFrameRelationPreserved context original trace.run.caller
            trace.run.returned) ∧
        (∀ original,
          NestedMixedFrameRelationPreserved context world original
            trace.run.caller trace.run.returned)

structure CompiledKernelCallbackEntriesRefine
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelCallbackInventory) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop) : Prop where
  exactCoverage : inventory.checked program pe imports = true
  siteRefinement : ∀ site ∈ inventory.sites,
    KernelIndirectCallbackEntryRefinement context world site (cells site)
      program pe imports (contracts site) (sourceInvariant site) (runs site)

/-! The generated bridge enters an external target by jumping to a one-byte
`ret` trampoline with `[target, capture]` on the physical stack.  This static
record classifies only the PE-owned trampoline and capture continuation.  The
runtime target identity and environment effect remain proof obligations. -/

structure KernelExternalRetTrampolineSite where
  id : Nat
  instruction : KernelInstruction
  captureRva : Nat
  imported : PEImport
deriving Repr, DecidableEq

def KernelExternalRetTrampolineSite.checked
    (site : KernelExternalRetTrampolineSite) (pe : PE32)
    (imports : List PEImport) : Bool :=
  site.instruction.checked pe imports && imports.contains site.imported &&
    executableRva pe site.captureRva &&
    match site.instruction.decode? pe with
    | some decoded =>
        decoded.instruction == .ret &&
          decoded.size == site.instruction.bytes.length
    | none => false

structure KernelExternalRetTrampolineInventory where
  sites : List KernelExternalRetTrampolineSite
deriving Repr, DecidableEq

def KernelExternalRetTrampolineInventory.checked
    (inventory : KernelExternalRetTrampolineInventory) (pe : PE32)
    (imports : List PEImport) : Bool :=
  decide (inventory.sites.map (·.id)).Nodup &&
    decide (inventory.sites.map (·.instruction.rva)).Nodup &&
    inventory.sites.all (·.checked pe imports)

/-- Machine-level meaning of one ret-trampoline target.  A final acceptance
proof supplies this relation from its paired external-environment theorem;
generated static data cannot choose it. -/
structure KernelExternalRetTrampolineContract where
  targetMatches : MachineState -> Word -> Prop
  arguments : MachineState -> List Word
  effect : NativeExternalEvent -> MachineState -> Prop

def ExternalRetTrampolineBoundaryHolds
    (site : KernelExternalRetTrampolineSite)
    (contract : KernelExternalRetTrampolineContract)
    (pe : PE32) (environment : NativeEnvironment) (eventIndex : Nat)
    (caller calleeEntry returned : MachineState) (target : Word)
    (event : NativeExternalEvent) : Prop :=
  contract.targetMatches caller target ∧
    Memory.read32 calleeEntry.memory calleeEntry.registers.esp =
      BitVec.ofNat 32 (pe.imageBase + site.captureRva) ∧
    event.imported = site.imported ∧
    event.arguments = contract.arguments calleeEntry ∧
    event.state = calleeEntry ∧
    returned = environment.result eventIndex event ∧
    contract.effect event returned

/-- One classified indirect call entry.  The exact PE instruction performs
the hardware return-address push.  The target is selected from a finite set
whose runtime pointer cell and full target execution are proved by the site
refinement. -/
structure CheckedCallbackIndirectStep
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelCallbackInventory) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop)
    (before after : NativeExecution) where
  site : KernelIndirectCallbackSite
  siteMember : site ∈ inventory.sites
  callbacks : CompiledKernelCallbackEntriesRefine context world inventory
    program pe imports cells contracts sourceInvariant runs
  trace : KernelCallbackExecutionTrace
  executed : runs site trace
  source : sourceInvariant site trace.run.caller
  target : CallbackTargetEntry
  targetMember : target ∈ site.targets.entries
  targetEvidence :
    trace.run.target = target.address pe ∧
    site.targetWord trace.run.caller = target.address pe ∧
    (cells site).CellHoldsFor pe target trace.run.caller ∧
    ExactCDeclCallHolds pe site trace.run ∧
    (contracts site).effect target trace.run.arguments trace.run.result
      trace.run.calleeEntry trace.run.returned trace.emittedEvents ∧
    (∀ original,
      NestedFrameRelationPreserved context original trace.run.caller
        trace.run.returned) ∧
    (∀ original,
      NestedMixedFrameRelationPreserved context world original
        trace.run.caller trace.run.returned)
  undefinedSlot : Nat
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  beforeShape : before = .running site.instruction.rva undefinedSlot
    trace.run.caller calls eventIndex events
  exactInstruction :
    stepKernelPE32Instruction pe imports
      (.running site.instruction.rva undefinedSlot trace.run.caller) =
        .stopped (.indirectCall trace.run.target site.continuationRva
          (pe.imageBase + site.continuationRva)) trace.run.calleeEntry
  afterShape : after = .running target.entry.rva 0 trace.run.calleeEntry
    ({ continuationRva := site.continuationRva,
       returnAddress := BitVec.ofNat 32
         (pe.imageBase + site.continuationRva) } :: calls)
    eventIndex events

theorem CheckedCallbackIndirectStep.refinesTarget
    {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {before after : NativeExecution}
    (step : CheckedCallbackIndirectStep context world inventory program pe
      imports environment cells contracts sourceInvariant runs before after) :
    ∃ target ∈ step.site.targets.entries,
      step.trace.run.target = target.address pe ∧
      ExactCDeclCallHolds pe step.site step.trace.run := by
  refine ⟨step.target, step.targetMember, step.targetEvidence.1, ?_⟩
  · exact step.targetEvidence.2.2.2.1

/-- One external bridge ret-trampoline.  Its exact PE `ret` pops the dynamic
target and exposes the statically checked capture continuation.  The paired
environment contract supplies target identity, arguments, result, and frame
preservation. -/
structure CheckedExternalRetTrampolineStep
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelExternalRetTrampolineInventory)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (contracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (before after : NativeExecution) where
  site : KernelExternalRetTrampolineSite
  siteMember : site ∈ inventory.sites
  inventoryChecked : inventory.checked pe imports = true
  undefinedSlot : Nat
  caller : MachineState
  calleeEntry : MachineState
  returned : MachineState
  target : Word
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  event : NativeExternalEvent
  beforeShape : before = .running site.instruction.rva undefinedSlot caller
    calls eventIndex events
  exactInstruction :
    stepPE32Instruction pe imports
      (.running site.instruction.rva undefinedSlot caller) =
        .stopped (.returned target) calleeEntry
  boundary : ExternalRetTrampolineBoundaryHolds site (contracts site) pe
    environment eventIndex caller calleeEntry returned target event
  linkedFrames : ∀ original,
    NestedFrameRelationPreserved context original caller returned
  mixedFrames : ∀ original,
    NestedMixedFrameRelationPreserved context world original caller returned
  afterShape : after = .running site.captureRva 0 returned calls
    (eventIndex + 1) (events ++ [event])

/-! Finite callback-aware execution.  Ordinary steps delegate to the original
fail-closed executor unchanged.  The two additional constructors are available
only with the checked finite-target or ret-trampoline proof objects above. -/
inductive CallbackAwareNativeSteps
    (context : StaticProofContext) (world : RelationalWorld)
    (callbackInventory : KernelCallbackInventory)
    (trampolineInventory : KernelExternalRetTrampolineInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract)
    (trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop) :
    NativeExecution -> NativeExecution -> Prop
  | refl (state) : CallbackAwareNativeSteps context world callbackInventory
      trampolineInventory program pe imports environment cells callbackContracts
      trampolineContracts sourceInvariant runs state state
  | ordinary (before middle after) :
      stepNativeExecution pe imports environment before = middle ->
      CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs middle after ->
      CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs before after
  | indirect (before targetEntry continuation after)
      (step : CheckedCallbackIndirectStep context world callbackInventory
        program pe imports environment cells callbackContracts sourceInvariant
        runs before targetEntry)
      (targetExecution : CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs targetEntry
          continuation)
      (continuationShape : continuation = .running step.site.continuationRva 0
        step.trace.run.returned step.calls step.trace.afterEventIndex
        (step.events ++ step.trace.emittedEvents))
      (eventAccounting : step.trace.afterEventIndex =
        step.eventIndex + step.trace.emittedEvents.length)
      (rest : CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs continuation
          after) :
      CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs before after
  | externalRet (before middle after) :
      CheckedExternalRetTrampolineStep context world trampolineInventory pe
        imports environment trampolineContracts before middle ->
      CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs middle after ->
      CallbackAwareNativeSteps context world callbackInventory
        trampolineInventory program pe imports environment cells
        callbackContracts trampolineContracts sourceInvariant runs before after

theorem NativeSteps.toCallbackAware
    {context : StaticProofContext} {world : RelationalWorld}
    {callbackInventory : KernelCallbackInventory}
    {trampolineInventory : KernelExternalRetTrampolineInventory}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {before after : NativeExecution}
    (steps : NativeSteps pe imports environment before after) :
    CallbackAwareNativeSteps context world callbackInventory
      trampolineInventory program pe imports environment cells callbackContracts
      trampolineContracts sourceInvariant runs before after := by
  induction steps with
  | refl state => exact CallbackAwareNativeSteps.refl state
  | tail before middle after stepped _ induction =>
      exact CallbackAwareNativeSteps.ordinary before middle after stepped induction

/-- The unchanged base executor deliberately stops at a classified indirect
boundary.  Callback-aware execution extends the proof relation, not this
function. -/
theorem stepNativeExecution_eq_unsupportedIndirect_of_exact_indirect
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (rva undefinedSlot : Nat) (state next : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (target : Word)
    (continuationRva returnAddress : Nat)
    (exact : stepKernelPE32Instruction pe imports
      (.running rva undefinedSlot state) =
      .stopped (.indirectCall target continuationRva returnAddress) next) :
    stepNativeExecution pe imports environment
      (.running rva undefinedSlot state calls eventIndex events) =
        .unsupportedIndirect rva target := by
  simp [stepNativeExecution, exact, nextNativeExecution]
  rfl

def CallbackAwareNativeDispatches
    (context : StaticProofContext) (world : RelationalWorld)
    (callbackInventory : KernelCallbackInventory)
    (trampolineInventory : KernelExternalRetTrampolineInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract)
    (trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop)
    (entryRva : Nat) (before after : MachineState)
    (events : List NativeExternalEvent) : Prop :=
  CallbackAwareNativeSteps context world callbackInventory trampolineInventory
    program pe imports environment cells callbackContracts trampolineContracts
    sourceInvariant runs (.running entryRva 0 before [] 0 [])
      (.returned after events)

theorem NativeDispatches.toCallbackAware
    {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory}
    {trampolines : KernelExternalRetTrampolineInventory}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {entryRva : Nat} {before after : MachineState}
    {events : List NativeExternalEvent}
    (dispatches : NativeDispatches pe imports environment entryRva before after
      events) :
    CallbackAwareNativeDispatches context world inventory trampolines program
      pe imports environment cells callbackContracts trampolineContracts
      sourceInvariant runs entryRva before after events :=
  NativeSteps.toCallbackAware dispatches

/-- Kernel-operation refinement specialized to the concrete callback-aware
dispatch semantics.  This is definitionally `KernelOperationRefinesUsing`;
the named specialization keeps downstream theorem signatures stable. -/
def KernelOperationCallbackRefines
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelCallbackInventory)
    (trampolines : KernelExternalRetTrampolineInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (abi : KernelABIRelation)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract)
    (trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop)
    (operation : KernelOperation) : Prop :=
  KernelOperationRefinesUsing program abi
    (CallbackAwareNativeDispatches context world inventory trampolines program
      pe imports environment cells callbackContracts trampolineContracts
      sourceInvariant runs) operation

theorem KernelOperationRefines.toCallbackAware
    {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory}
    {trampolines : KernelExternalRetTrampolineInventory}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {abi : KernelABIRelation}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {callbackContracts : KernelIndirectCallbackSite ->
      KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {operation : KernelOperation}
    (refinement : KernelOperationRefines program pe imports environment abi
      operation) :
    KernelOperationCallbackRefines context world inventory trampolines program
      pe imports environment abi cells callbackContracts trampolineContracts
      sourceInvariant runs operation := by
  intro request before operationMatches related response transition
  obtain ⟨entryRva, after, events, entry, execution, responseRelated, frame⟩ :=
    refinement request before operationMatches related response transition
  exact ⟨entryRva, after, events, entry,
    NativeDispatches.toCallbackAware execution,
    responseRelated, frame⟩

theorem KernelIndirectCallbackExecutionRefinement.sound
    {context : StaticProofContext} {world : RelationalWorld}
    {site : KernelIndirectCallbackSite}
    {cells : RelocationBackedCallbackTargetInventory}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {contract : KernelCallbackTargetContract}
    {sourceInvariant : MachineState -> Prop}
    {runs : KernelCallbackExecutionTrace -> Prop}
    (certificate : KernelIndirectCallbackExecutionRefinement context world site
      cells program pe imports environment contract sourceInvariant runs)
    (trace : KernelCallbackExecutionTrace) (executed : runs trace)
    (source : sourceInvariant trace.run.caller) :
    ∃ target ∈ site.targets.entries,
      trace.run.target = target.address pe ∧
      site.targetWord trace.run.caller = target.address pe ∧
      cells.CellHoldsFor pe target trace.run.caller ∧
      ExactCDeclCallHolds pe site trace.run ∧
      ExactCallbackTargetExecution site target pe imports environment trace ∧
      contract.effect target trace.run.arguments trace.run.result
        trace.run.calleeEntry trace.run.returned trace.emittedEvents ∧
      (∀ original,
        NestedFrameRelationPreserved context original trace.run.caller
          trace.run.returned) ∧
      (∀ original,
        NestedMixedFrameRelationPreserved context world original
          trace.run.caller trace.run.returned) :=
  certificate.runRefines trace executed source

/-! Whole-operation callback closure.  This certificate specializes
`KernelOperationRefinesUsing`: every decoded indirect call in the rooted kernel has
finite static coverage, relocation-backed runtime provenance, a total run
witness on its source invariant, exact target execution, and environment
effect refinement.  Its simulation field exhibits the concrete checked
callback-aware dispatch relation; no generated status can assert execution. -/
structure KernelOperationCallbackCertificate
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : KernelCallbackInventory) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (abi : KernelABIRelation)
    (trampolines : KernelExternalRetTrampolineInventory)
    (cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory)
    (contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract)
    (trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract)
    (sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop)
    (runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop)
    (operation : KernelOperation) : Prop where
  callbacks : CompiledKernelCallbackEntriesRefine context world inventory
    program pe imports cells contracts sourceInvariant runs
  exactRetTrampolines : trampolines.checked pe imports = true
  simulate : ∀ request before,
    request.operation = operation -> abi.requestRelated request before ->
    ∀ response, AbstractKernelTransition request response ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? operation.role = some entryRva ∧
        CallbackAwareNativeDispatches context world inventory trampolines program
          pe imports environment cells contracts trampolineContracts
          sourceInvariant runs entryRva before after nativeEvents ∧
        abi.responseRelated request response after nativeEvents ∧
        MemoryAgreesOutside (abi.scratchFootprint request)
          after.memory before.memory

theorem KernelOperationCallbackCertificate.refines
    {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {abi : KernelABIRelation}
    {trampolines : KernelExternalRetTrampolineInventory}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {operation : KernelOperation}
    (certificate : KernelOperationCallbackCertificate context world inventory
      program pe imports environment abi trampolines cells contracts
      trampolineContracts sourceInvariant runs operation) :
    KernelOperationCallbackRefines context world inventory trampolines program
      pe imports environment abi cells contracts trampolineContracts
      sourceInvariant runs operation :=
  certificate.simulate

#print axioms KernelIndirectCallbackExecutionRefinement.sound
#print axioms CheckedCallbackIndirectStep.refinesTarget
#print axioms NativeSteps.toCallbackAware
#print axioms NativeDispatches.toCallbackAware
#print axioms stepNativeExecution_eq_unsupportedIndirect_of_exact_indirect
#print axioms KernelOperationRefines.toCallbackAware
#print axioms KernelOperationCallbackCertificate.refines

end StageA.Relational.InterpreterKernelCallback
