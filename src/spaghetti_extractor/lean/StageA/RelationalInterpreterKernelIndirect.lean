import StageA.RelationalInterpreterKernelCallback

namespace StageA.Relational.InterpreterKernelIndirect

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback

/-! A fail-closed classifier for indirect calls in compiled kernels.  The
on-disk relocation is only initialization evidence.  Writable cells therefore
remain dynamic invariants and cannot acquire immutable-image authority. -/

inductive RelocationTargetSectionKind where
  | immutable
  | writable
deriving Repr, DecidableEq

def wordSection? (pe : PE32) (rva : Nat) : Option Section :=
  match pe.sections.filter fun sec =>
      sec.virtualAddress <= rva &&
        rva + 4 <= sec.virtualAddress + sec.mappedSize with
  | [sec] => some sec
  | _ => none

def RelocationTargetSectionKind.matches
    (kind : RelocationTargetSectionKind) (sec : Section) : Bool :=
  match kind with
  | .immutable => !sec.writable
  | .writable => sec.writable

structure ClassifiedRelocationTargetCell where
  cell : RelocationBackedCallbackTargetCell
  sectionKind : RelocationTargetSectionKind
deriving Repr, DecidableEq

def ClassifiedRelocationTargetCell.checked
    (classified : ClassifiedRelocationTargetCell) (pe : PE32)
    (relocations : List BaseRelocation) (targets : CallbackTargetSet) : Bool :=
  classified.cell.checked pe relocations targets &&
    match wordSection? pe classified.cell.cellRva with
    | none => false
    | some sec => classified.sectionKind.matches sec

def ClassifiedRelocationTargetCell.Holds
    (classified : ClassifiedRelocationTargetCell) (pe : PE32)
    (targets : CallbackTargetSet) (state : MachineState) : Prop :=
  ∃ target ∈ targets.entries,
    classified.cell.Holds pe target state

structure ClassifiedRelocationTargetInventory where
  cells : List ClassifiedRelocationTargetCell
deriving Repr, DecidableEq

def ClassifiedRelocationTargetInventory.erased
    (inventory : ClassifiedRelocationTargetInventory) :
    RelocationBackedCallbackTargetInventory := {
  cells := inventory.cells.map (·.cell)
}

def ClassifiedRelocationTargetInventory.checked
    (inventory : ClassifiedRelocationTargetInventory)
    (pe : PE32) (targets : CallbackTargetSet) : Bool :=
  match parseRelocations pe with
  | none => false
  | some relocations =>
      inventory.erased.checked pe targets &&
        inventory.cells.all (·.checked pe relocations targets)

def ClassifiedRelocationTargetInventory.RuntimeValuesBounded
    (inventory : ClassifiedRelocationTargetInventory)
    (pe : PE32) (targets : CallbackTargetSet) (state : MachineState) : Prop :=
  ∀ cell ∈ inventory.cells, cell.Holds pe targets state

def ClassifiedRelocationTargetInventory.WritableCellsPreserved
    (inventory : ClassifiedRelocationTargetInventory)
    (pe : PE32) (before after : MachineState) : Prop :=
  ∀ cell ∈ inventory.cells, cell.sectionKind = .writable ->
    Memory.read32 before.memory
        (BitVec.ofNat 32 (pe.imageBase + cell.cell.cellRva)) =
      Memory.read32 after.memory
        (BitVec.ofNat 32 (pe.imageBase + cell.cell.cellRva))

structure ClassifiedFiniteIndirectSite where
  site : KernelIndirectCallbackSite
  cells : ClassifiedRelocationTargetInventory
deriving Repr, DecidableEq

def ClassifiedFiniteIndirectSite.checked
    (classified : ClassifiedFiniteIndirectSite)
    (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) : Bool :=
  classified.site.checked pe imports &&
    compiledKernelProgramContainsInstructionRva program
      classified.site.instruction.rva &&
    classified.cells.checked pe classified.site.targets

/-! Direct IAT calls are finite by import identity rather than by an internal
executable address.  This record deliberately accepts only `call [absolute]`;
register-carried or writable copied IAT values require a separate provenance
proof and remain incomplete in this profile. -/

structure ClassifiedIATIndirectSite where
  id : Nat
  instruction : KernelInstruction
  continuationRva : Nat
  targetOperand : Operand32
  abi : CDeclMachineABI
  imported : PEImport
deriving Repr, DecidableEq

def ClassifiedIATIndirectSite.operandChecked
    (site : ClassifiedIATIndirectSite) (pe : PE32) : Bool :=
  match site.targetOperand with
  | .memory addressing =>
      addressing.base.isNone && addressing.index.isNone &&
        addressing.scaleShift == 0 &&
        addressing.displacement == pe.imageBase + site.imported.iatRva
  | _ => false

def ClassifiedIATIndirectSite.decodedExact
    (site : ClassifiedIATIndirectSite) (pe : PE32) : Bool :=
  match site.instruction.decode? pe with
  | some decoded =>
      decoded.instruction == .callIndirect site.targetOperand &&
        decoded.size == site.instruction.bytes.length &&
        site.continuationRva == site.instruction.rva + decoded.size
  | none => false

def ClassifiedIATIndirectSite.checked
    (site : ClassifiedIATIndirectSite) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) : Bool :=
  parseImports pe == some imports && imports.contains site.imported &&
    site.operandChecked pe && site.decodedExact pe && site.abi.checked &&
    site.instruction.checked pe imports &&
    compiledKernelProgramContainsInstructionRva program site.instruction.rva

def ClassifiedIATIndirectSite.asCallbackSite
    (site : ClassifiedIATIndirectSite) : KernelIndirectCallbackSite := {
  id := site.id
  instruction := site.instruction
  continuationRva := site.continuationRva
  targetOperand := site.targetOperand
  abi := site.abi
  targets := { entries := [] }
}

inductive ClassifiedKernelIndirectSite where
  | relocated (site : ClassifiedFiniteIndirectSite)
  | iat (site : ClassifiedIATIndirectSite)
deriving Repr, DecidableEq

def ClassifiedKernelIndirectSite.id : ClassifiedKernelIndirectSite -> Nat
  | .relocated site => site.site.id
  | .iat site => site.id

def ClassifiedKernelIndirectSite.rva : ClassifiedKernelIndirectSite -> Nat
  | .relocated site => site.site.instruction.rva
  | .iat site => site.instruction.rva

def ClassifiedKernelIndirectSite.checked
    (site : ClassifiedKernelIndirectSite) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) : Bool :=
  match site with
  | .relocated site => site.checked program pe imports
  | .iat site => site.checked program pe imports

def classifiedIndirectSitesContainRva
    (sites : List ClassifiedKernelIndirectSite) (rva : Nat) : Bool :=
  sites.any fun site => site.rva == rva

structure ClassifiedKernelIndirectInventory where
  sites : List ClassifiedKernelIndirectSite
deriving Repr, DecidableEq

def ClassifiedKernelIndirectInventory.coversProgram
    (inventory : ClassifiedKernelIndirectInventory)
    (program : CompiledKernelProgram) (pe : PE32) : Bool :=
  program.functions.all fun function =>
    function.blocks.all fun block =>
      block.instructions.all fun instruction =>
        match instruction.decode? pe with
        | none => false
        | some decoded =>
            match decoded.instruction with
            | .callIndirect _ =>
                classifiedIndirectSitesContainRva inventory.sites instruction.rva
            | _ => true

def ClassifiedKernelIndirectInventory.checked
    (inventory : ClassifiedKernelIndirectInventory)
    (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) : Bool :=
  decide (inventory.sites.map (·.id)).Nodup &&
    decide (inventory.sites.map (·.rva)).Nodup &&
    inventory.sites.all (·.checked program pe imports) &&
    inventory.coversProgram program pe

/-! Static classification never closes runtime membership.  This certificate
connects a classified writable or immutable cell to the exact cdecl boundary,
the checked continuation, nested frames, and exact execution of one finite
target. -/

structure ClassifiedFiniteIndirectRefinement
    (context : StaticProofContext) (world : RelationalWorld)
    (classified : ClassifiedFiniteIndirectSite)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (contract : KernelCallbackTargetContract)
    (sourceInvariant : MachineState -> Prop)
    (runs : KernelCallbackExecutionTrace -> Prop) : Prop where
  staticClassification : classified.checked program pe imports = true
  sourceValuesBounded : ∀ state, sourceInvariant state ->
    classified.cells.RuntimeValuesBounded pe classified.site.targets state
  execution : KernelIndirectCallbackExecutionRefinement context world
    classified.site classified.cells.erased program pe imports environment
    contract sourceInvariant runs

theorem ClassifiedFiniteIndirectRefinement.sound
    {context : StaticProofContext} {world : RelationalWorld}
    {classified : ClassifiedFiniteIndirectSite}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {contract : KernelCallbackTargetContract}
    {sourceInvariant : MachineState -> Prop}
    {runs : KernelCallbackExecutionTrace -> Prop}
    (certificate : ClassifiedFiniteIndirectRefinement context world classified
      program pe imports environment contract sourceInvariant runs)
    (trace : KernelCallbackExecutionTrace) (executed : runs trace)
    (source : sourceInvariant trace.run.caller) :
    ∃ target ∈ classified.site.targets.entries,
      trace.run.target = target.address pe ∧
      classified.site.targetWord trace.run.caller = target.address pe ∧
      ExactCDeclCallHolds pe classified.site trace.run ∧
      ExactCallbackTargetExecution classified.site target pe imports environment
        trace := by
  obtain ⟨target, member, runTarget, sourceTarget, _cell, abi, execution,
      _effect, _linked, _mixed⟩ :=
    certificate.execution.sound trace executed source
  exact ⟨target, member, runTarget, sourceTarget, abi, execution⟩

structure KernelIATCallContract where
  targetMatches : PEImport -> Word -> Prop
  effect : NativeExternalEvent -> MachineState -> Prop

structure ClassifiedIATIndirectRefinement
    (context : StaticProofContext) (world : RelationalWorld)
    (site : ClassifiedIATIndirectSite) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (contract : KernelIATCallContract)
    (sourceInvariant : MachineState -> Prop)
    (runs : KernelCallbackExecutionTrace -> Prop) : Prop where
  staticClassification : site.checked program pe imports = true
  runForSource : ∀ state, sourceInvariant state ->
    ∃ trace, runs trace ∧ trace.run.caller = state
  runRefines : ∀ trace, runs trace -> sourceInvariant trace.run.caller ->
    trace.run.target = site.asCallbackSite.targetWord trace.run.caller ∧
      contract.targetMatches site.imported trace.run.target ∧
      ExactCDeclCallHolds pe site.asCallbackSite trace.run ∧
      (∀ original, NestedFrameRelationPreserved context original
        trace.run.caller trace.run.returned) ∧
      (∀ original, NestedMixedFrameRelationPreserved context world original
        trace.run.caller trace.run.returned) ∧
      ∀ event ∈ trace.emittedEvents, contract.effect event trace.run.returned

structure ClassifiedKernelIndirectCallsRefine
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ClassifiedKernelIndirectInventory)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment)
    (internalContract : ClassifiedFiniteIndirectSite ->
      KernelCallbackTargetContract)
    (internalInvariant : ClassifiedFiniteIndirectSite -> MachineState -> Prop)
    (internalRuns : ClassifiedFiniteIndirectSite ->
      KernelCallbackExecutionTrace -> Prop)
    (iatContract : ClassifiedIATIndirectSite -> KernelIATCallContract)
    (iatInvariant : ClassifiedIATIndirectSite -> MachineState -> Prop)
    (iatRuns : ClassifiedIATIndirectSite ->
      KernelCallbackExecutionTrace -> Prop) : Prop where
  exactCoverage : inventory.checked program pe imports = true
  internalRefinement : ∀ site,
    .relocated site ∈ inventory.sites ->
      ClassifiedFiniteIndirectRefinement context world site program pe imports
        environment (internalContract site) (internalInvariant site)
        (internalRuns site)
  iatRefinement : ∀ site, .iat site ∈ inventory.sites ->
    ClassifiedIATIndirectRefinement context world site program pe imports
      (iatContract site) (iatInvariant site) (iatRuns site)

#print axioms ClassifiedFiniteIndirectRefinement.sound

end StageA.Relational.InterpreterKernelIndirect
