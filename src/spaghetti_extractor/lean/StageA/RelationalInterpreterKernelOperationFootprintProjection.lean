import StageA.RelationalInterpreterKernelEngineCopy
import StageA.RelationalInterpreterKernelOperationMemoryRoute
import StageA.RelationalInterpreterKernelOperationProjection

namespace StageA.Relational.InterpreterKernelOperationFootprintProjection

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelEngineCopy
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Compact concrete-footprint projections

These theorems sit above the engine-range and symbolic-write definitions.
Keeping them out of the instruction-projection kernel avoids making ordinary
register projections depend on the heavier ABI framing closure.
-/

/-- A behavior with an exactly empty write list has an empty concrete
footprint for every input state. -/
theorem symbolicWriteFootprint_disjoint_of_writes_nil
    (domain : CandidateFootprint) (behavior : SymbolicBehavior)
    (state : MachineState) (writesExact : behavior.writes = []) :
    CandidateFootprintsDisjoint domain
      (symbolicWriteFootprint behavior state).contains := by
  intro address _ member
  change address ∈
    deduplicateWords (symbolicWriteBytes behavior state) at member
  have raw :=
    (mem_deduplicateWords address
      (symbolicWriteBytes behavior state)).mp member
  have impossible : address ∈ ([] : List Word) := by
    simpa only [symbolicWriteBytes, writesExact, List.flatMap_nil] using raw
  exact List.not_mem_nil impossible

/-- A checked singleton write is disjoint from a non-wrapping protected range
when every concrete byte of the write is at or beyond the range end. -/
theorem symbolicWriteFootprint_disjoint_wordRange_singleton
    (base : Word) (size : Nat) (behavior : SymbolicBehavior)
    (state : MachineState) (address value : Expr)
    (writeAddress : Word)
    (writesExact : behavior.writes = [(address, value)])
    (addressExact : address.eval state = writeAddress)
    (bytesAfter : ∀ byte,
      byte ∈ wordByteAddresses writeAddress ->
        base.toNat + size <= byte.toNat) :
    CandidateFootprintsDisjoint (CandidateWordRange base size)
      (symbolicWriteFootprint behavior state).contains := by
  intro byte inRange member
  change byte ∈
    deduplicateWords (symbolicWriteBytes behavior state) at member
  have raw :=
    (mem_deduplicateWords byte
      (symbolicWriteBytes behavior state)).mp member
  have writeByte : byte ∈ wordByteAddresses writeAddress := by
    simpa only [symbolicWriteBytes, writesExact, List.flatMap_cons,
      List.flatMap_nil, List.append_nil, addressExact] using raw
  have after := bytesAfter byte writeByte
  exact Nat.not_lt_of_ge after inRange.2

theorem CheckedNativeOperationRunningEdge.footprintDisjoint_of_writes_nil
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (domain : CandidateFootprint) (state : MachineState)
    (writesExact : edge.replay.behavior.writes = []) :
    CandidateFootprintsDisjoint domain
      (symbolicWriteFootprint edge.replay.behavior state).contains :=
  symbolicWriteFootprint_disjoint_of_writes_nil
    domain edge.replay.behavior state writesExact

theorem CheckedNativeOperationStoppedEdge.footprintDisjoint_of_writes_nil
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (domain : CandidateFootprint) (state : MachineState)
    (writesExact : edge.replay.behavior.writes = []) :
    CandidateFootprintsDisjoint domain
      (edge.cutpoint.postcondition.writeFootprint state).contains :=
  symbolicWriteFootprint_disjoint_of_writes_nil
    domain edge.replay.behavior state writesExact

theorem CheckedNativeOperationRunningEdge.footprintDisjoint_wordRange_singleton
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (base : Word) (size : Nat) (state : MachineState)
    (address value : Expr) (writeAddress : Word)
    (writesExact : edge.replay.behavior.writes = [(address, value)])
    (addressExact : address.eval state = writeAddress)
    (bytesAfter : ∀ byte,
      byte ∈ wordByteAddresses writeAddress ->
        base.toNat + size <= byte.toNat) :
    CandidateFootprintsDisjoint (CandidateWordRange base size)
      (symbolicWriteFootprint edge.replay.behavior state).contains :=
  symbolicWriteFootprint_disjoint_wordRange_singleton
    base size edge.replay.behavior state address value writeAddress
    writesExact addressExact bytesAfter

theorem checkedNativeOperationRunningTraceFootprintsDisjointAt_cons_projected
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (tail : List (CheckedNativeOperationRunningEdge candidate))
    (domain : CandidateFootprint)
    (source projected : MachineState)
    (projectedExact : projected = edge.after source)
    (headDisjoint :
      CandidateFootprintsDisjoint domain
        (symbolicWriteFootprint edge.replay.behavior source).contains)
    (tailDisjoint :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        tail domain projected) :
    checkedNativeOperationRunningTraceFootprintsDisjointAt
      (edge :: tail) domain source := by
  exact And.intro headDisjoint
    ((congrArg
      (checkedNativeOperationRunningTraceFootprintsDisjointAt tail domain)
      projectedExact).mp tailDisjoint)

theorem checkedNativeOperationBlockFootprintsDisjointAt_of_exact
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (trace : CheckedNativeOperationRunningTrace candidate)
    (domain : CandidateFootprint) (state : MachineState)
    (runningExact : block.running = some trace)
    (runningDisjoint :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        trace.edges domain state)
    (terminalDisjoint :
      CandidateFootprintsDisjoint domain
        (block.terminal.cutpoint.postcondition.writeFootprint
          (block.terminalState state)).contains) :
    checkedNativeOperationBlockFootprintsDisjointAt
      block domain state := by
  simpa only [checkedNativeOperationBlockFootprintsDisjointAt,
    runningExact] using And.intro runningDisjoint terminalDisjoint

#print axioms symbolicWriteFootprint_disjoint_of_writes_nil
#print axioms symbolicWriteFootprint_disjoint_wordRange_singleton
#print axioms CheckedNativeOperationRunningEdge.footprintDisjoint_of_writes_nil
#print axioms CheckedNativeOperationStoppedEdge.footprintDisjoint_of_writes_nil
#print axioms CheckedNativeOperationRunningEdge.footprintDisjoint_wordRange_singleton
#print axioms checkedNativeOperationRunningTraceFootprintsDisjointAt_cons_projected
#print axioms checkedNativeOperationBlockFootprintsDisjointAt_of_exact

end StageA.Relational.InterpreterKernelOperationFootprintProjection
