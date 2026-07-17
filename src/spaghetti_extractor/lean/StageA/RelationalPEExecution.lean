import StageA.Relational

namespace StageA.Relational

open StageA.Formal

/-- A fail-closed instruction fetch from the immutable mapped PE image. IA-32
instructions are at most 15 bytes; fetching stops at the containing executable
section boundary. Overlapping executable sections are rejected. -/
def executableInstructionWindow (pe : PE32) (rva : Nat) : Option Bytes :=
  match pe.sections.filter fun sec =>
      sec.executable && sec.virtualAddress <= rva &&
        rva < sec.virtualAddress + sec.mappedSize with
  | [sec] =>
      let available := sec.virtualAddress + sec.mappedSize - rva
      spanBytes pe { start := rva, size := min 15 available }
  | _ => none

def concreteBehaviorNextMachineState
    (behavior : ConcreteBehavior) (input : MachineState) : MachineState := {
  registers := behavior.registers
  memory := behavior.memory
  undefinedValue := input.undefinedValue
  x87 := {
    stack := fun index =>
      (behavior.x87.stack.drop index).head?.getD (BitVec.ofNat 80 0)
    control := behavior.x87.control
    status := behavior.x87.status
    semantics := input.x87.semantics
  }
  eflags := behavior.eflags
  fsBase := input.fsBase
}

/-- One exact instruction step selected by a concrete PE-relative program
counter. Internal fallthrough remains `running`; every decoded control effect
is exposed as a concrete outcome for the world semantics to handle. -/
inductive PE32InstructionExecution where
  | running (rva undefinedSlot : Nat) (state : MachineState)
  | stopped (outcome : ConcreteOutcome) (state : MachineState)
  | fault

def stepPE32Instruction (pe : PE32) (imports : List PEImport) :
    PE32InstructionExecution -> PE32InstructionExecution
  | .running rva undefinedSlot state =>
      match executableInstructionWindow pe rva with
      | none => .fault
      | some bytes =>
          match decodeInstructionExact bytes with
          | none => .fault
          | some decoded =>
              match executeInstruction pe imports rva undefinedSlot decoded initialSymbolic with
              | none => .fault
              | some (.next symbolic) =>
                  let concrete := symbolic.eval state
                  match concrete.outcome with
                  | some _ => .fault
                  | none => .running (rva + decoded.size) (undefinedSlot + 1)
                      (concreteBehaviorNextMachineState concrete state)
              | some (.stop symbolic) =>
                  let concrete := symbolic.eval state
                  match concrete.outcome with
                  | none => .fault
                  | some outcome => .stopped outcome
                      (concreteBehaviorNextMachineState concrete state)
  | terminal => terminal

def runPE32InstructionFuel (pe : PE32) (imports : List PEImport) :
    Nat -> PE32InstructionExecution -> PE32InstructionExecution
  | 0, execution => execution
  | fuel + 1, execution =>
      runPE32InstructionFuel pe imports fuel (stepPE32Instruction pe imports execution)

/-- Fetch the next instruction directly from the unique executable PE section,
without allowing the instruction to cross the declared cutpoint. -/
def executableSpanInstructionWindow (pe : PE32) (rva stop : Nat) : Option Bytes :=
  if rva < stop then
    match pe.sections.filter fun sec =>
        sec.executable && sec.virtualAddress <= rva &&
          stop <= sec.virtualAddress + sec.mappedSize with
    | [sec] =>
        spanBytes pe { start := rva, size := min 15 (stop - rva) }
    | _ => none
  else
    none

/-- Exact symbolic instruction execution from a PE address to a declared
cutpoint. The state carried between instructions is the reviewed symbolic x86
machine state. An ordinary instruction that reaches the cutpoint receives the
same explicit fallthrough outcome used by product-graph composition. -/
def runPE32SymbolicSpanFuel (pe : PE32) (imports : List PEImport)
    (stop : Nat) : Nat -> Nat -> Nat -> SymbolicBehavior -> Option SymbolicBehavior
  | 0, _, _, _ => none
  | fuel + 1, rva, undefinedSlot, symbolic =>
      if rva == stop then
        if symbolic.outcome.isSome then none
        else some { symbolic with outcome := some (.jump stop) }
      else if stop < rva then
        none
      else do
        let bytes <- executableSpanInstructionWindow pe rva stop
        let decoded <- decodeInstructionExact bytes
        if decoded.size == 0 || stop < rva + decoded.size then none else
        let result <- executeInstruction pe imports rva undefinedSlot decoded symbolic
        match result with
        | .next next =>
            runPE32SymbolicSpanFuel pe imports stop fuel (rva + decoded.size)
              (undefinedSlot + 1) next
        | .stop final =>
            if rva + decoded.size == stop then some final else none

def executePE32SymbolicSpan (pe : PE32) (imports : List PEImport)
    (span : Span) : Option SymbolicBehavior :=
  runPE32SymbolicSpanFuel pe imports span.stop (span.size + 1) span.start 0
    initialSymbolic

/-- Alias bridges may terminate with a direct jump before consuming all bytes
up to the canonical cutpoint. Fallthrough to the cutpoint is represented by an
explicit jump, matching the product-program entry convention. -/
def runPE32SymbolicAliasBridgeFuel (pe : PE32) (imports : List PEImport)
    (canonicalRva : Nat) : Nat -> Nat -> Nat -> SymbolicBehavior ->
      Option SymbolicBehavior
  | 0, _, _, _ => none
  | fuel + 1, rva, undefinedSlot, symbolic =>
      if rva == canonicalRva then
        if symbolic.outcome.isSome then none
        else some { symbolic with outcome := some (.jump canonicalRva) }
      else if canonicalRva < rva then
        none
      else do
        let bytes <- executableSpanInstructionWindow pe rva canonicalRva
        let decoded <- decodeInstructionExact bytes
        let result <- executeInstruction pe imports rva undefinedSlot decoded symbolic
        match result with
        | .next next =>
            runPE32SymbolicAliasBridgeFuel pe imports canonicalRva fuel
              (rva + decoded.size) (undefinedSlot + 1) next
        | .stop final => some final

def executePE32SymbolicAliasBridge (pe : PE32) (imports : List PEImport)
    (aliasRva canonicalRva : Nat) : Option SymbolicBehavior :=
  if canonicalRva <= aliasRva then none else
  runPE32SymbolicAliasBridgeFuel pe imports canonicalRva
    (canonicalRva - aliasRva + 1) aliasRva 0 initialSymbolic

def codeAliasInstructionSemanticallyValid (pe : PE32)
    (imports : List PEImport) (canonicalRva : Nat) (alias : CodeAlias) : Bool :=
  executePE32SymbolicAliasBridge pe imports alias.rva canonicalRva ==
    some { initialSymbolic with outcome := some (.jump canonicalRva) }

def StaticCodeMap.aliasesInstructionSemanticallyValidAt (candidate : Bool)
    (pe : PE32) (imports : List PEImport) (mapping : StaticCodeMap)
    (targetId : Nat) : Bool :=
  match mapping.get? targetId with
  | none => false
  | some target =>
      let canonicalRva := if candidate then target.candidateRva else target.originalRva
      let aliases := if candidate then target.candidateAliases else target.originalAliases
      aliases.all (codeAliasInstructionSemanticallyValid pe imports canonicalRva)

def StaticCodeMap.AliasesInstructionSemanticallyValid (candidate : Bool)
    (pe : PE32) (imports : List PEImport) (mapping : StaticCodeMap) : Prop :=
  ∀ targetId, targetId < mapping.entries.size ->
    mapping.aliasesInstructionSemanticallyValidAt candidate pe imports targetId = true

/-- Region-level semantics is adequate only when independently fetching each
instruction from the PE image produces the same non-failing symbolic macro
step as the bulk region decoder. This proposition is intended to be proved by
Lean computation for concrete regions, never copied from an extractor status. -/
def RegionInstructionAdequate (pe : PE32) (imports : List PEImport)
    (span : Span) : Prop :=
  ∃ symbolic,
    executePE32SymbolicSpan pe imports span = some symbolic ∧
      regionBehaviorWithImports pe imports span = some symbolic

def regionInstructionAdequateChecked (pe : PE32) (imports : List PEImport)
    (span : Span) : Bool :=
  match executePE32SymbolicSpan pe imports span,
      regionBehaviorWithImports pe imports span with
  | some executed, some decoded => executed == decoded
  | _, _ => false

theorem regionInstructionAdequate_of_checked (pe : PE32)
    (imports : List PEImport) (span : Span)
    (checked : regionInstructionAdequateChecked pe imports span = true) :
    RegionInstructionAdequate pe imports span := by
  unfold regionInstructionAdequateChecked at checked
  split at checked <;> try contradiction
  rename_i executed decoded executionResult decodeResult
  simp only [beq_iff_eq] at checked
  subst decoded
  exact ⟨executed, executionResult, decodeResult⟩

/-- A composable inventory of region-level instruction adequacy facts. The
candidate selector chooses the concrete side span; every item is still checked
against the corresponding PE bytes and import table. -/
def AllRegionInstructionAdequate (pe : PE32) (imports : List PEImport)
    (candidate : Bool) : List RegionRelation -> Prop
  | [] => True
  | region :: regions =>
      RegionInstructionAdequate pe imports
          (if candidate then region.candidate else region.original) ∧
        AllRegionInstructionAdequate pe imports candidate regions

theorem allRegionInstructionAdequate_append (pe : PE32)
    (imports : List PEImport) (candidate : Bool)
    (left right : List RegionRelation)
    (leftAdequate : AllRegionInstructionAdequate pe imports candidate left)
    (rightAdequate : AllRegionInstructionAdequate pe imports candidate right) :
    AllRegionInstructionAdequate pe imports candidate (left ++ right) := by
  induction left with
  | nil => simpa [AllRegionInstructionAdequate] using rightAdequate
  | cons region regions inductionHypothesis =>
      exact ⟨leftAdequate.1, inductionHypothesis leftAdequate.2⟩

theorem allRegionInstructionAdequate_member (pe : PE32)
    (imports : List PEImport) (candidate : Bool)
    (regions : List RegionRelation) (region : RegionRelation)
    (allAdequate : AllRegionInstructionAdequate pe imports candidate regions)
    (member : region ∈ regions) :
    RegionInstructionAdequate pe imports
      (if candidate then region.candidate else region.original) := by
  induction regions with
  | nil => simp at member
  | cons head tail inductionHypothesis =>
      simp only [List.mem_cons] at member
      cases member with
      | inl equal =>
          subst region
          exact allAdequate.1
      | inr tailMember =>
          exact inductionHypothesis allAdequate.2 tailMember

end StageA.Relational
