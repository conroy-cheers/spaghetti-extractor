import StageA.RelationalInterpreterKernelOperationPredicateRoute
import StageA.RelationalInterpreterKernelOperationProjection
import StageA.RelationalInterpreterKernelOperationStateRouteChecker

namespace StageA.Relational.InterpreterKernelOperationMemoryRoute

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.Engine
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Protected-memory composition for native-operation routes

Control-flow certificates and memory-frame certificates are intentionally
orthogonal. Exact symbolic execution supplies each instruction's write
footprint; generated modules only prove that a protected predicate is disjoint
from those checked footprints. The existing predicate route then composes the
result without another symbolic execution.
-/

def MemoryAgreesOn (domain : CandidateFootprint)
    (after before : Memory) : Prop :=
  forall address, domain address -> after address = before address

theorem MemoryAgreesOn.refl (domain : CandidateFootprint)
    (memory : Memory) :
    MemoryAgreesOn domain memory memory := by
  intro _ _
  rfl

theorem MemoryAgreesOn.trans
    {domain : CandidateFootprint} {before middle after : Memory}
    (first : MemoryAgreesOn domain middle before)
    (second : MemoryAgreesOn domain after middle) :
    MemoryAgreesOn domain after before := by
  intro address member
  rw [second address member, first address member]

theorem MemoryAgreesOn.mono
    {broader narrower : CandidateFootprint} {after before : Memory}
    (agrees : MemoryAgreesOn broader after before)
    (subset : ∀ address, narrower address -> broader address) :
    MemoryAgreesOn narrower after before := by
  intro address member
  exact agrees address (subset address member)

theorem MemoryAgreesOn.candidateMemoryAgreesOnRepresentation
    {rep : EngineRep} {after before : Memory}
    (agrees : MemoryAgreesOn (CandidateAddressObserved rep) after before) :
    CandidateMemoryAgreesOnRepresentation rep after before :=
  agrees

theorem checkedNativeOperationRunningEdge_memoryAgreesOn
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (domain : CandidateFootprint) (state : MachineState)
    (disjoint :
      CandidateFootprintsDisjoint domain
        (symbolicWriteFootprint edge.replay.behavior state).contains) :
    MemoryAgreesOn domain (edge.after state).memory state.memory := by
  have frame :=
    symbolicWriteFootprint.memoryFrame edge.replay.behavior state
  intro address member
  exact frame address (disjoint address member)

/-- A symbolic transition writes inside a concrete footprint when every byte
of every exact write expression evaluates into that footprint. -/
def symbolicBehaviorWritesInside
    (footprint : CandidateFootprint)
    (behavior : SymbolicBehavior) (state : MachineState) : Prop :=
  ∀ address, address ∈ symbolicWriteBytes behavior state ->
    footprint address

theorem symbolicBehaviorWritesInside_of_writes_nil
    (footprint : CandidateFootprint)
    (behavior : SymbolicBehavior) (state : MachineState)
    (writesExact : behavior.writes = []) :
    symbolicBehaviorWritesInside footprint behavior state := by
  intro address member
  have impossible : address ∈ ([] : List Word) := by
    simpa only [symbolicWriteBytes, writesExact, List.flatMap_nil] using member
  exact (List.not_mem_nil impossible).elim

theorem symbolicBehaviorWritesInside_of_writes_singleton
    (footprint : CandidateFootprint)
    (behavior : SymbolicBehavior) (state : MachineState)
    (address value : Expr) (concreteAddress : Word)
    (writesExact : behavior.writes = [(address, value)])
    (addressExact : address.eval state = concreteAddress)
    (inside : ∀ byte, byte ∈ wordByteAddresses concreteAddress ->
      footprint byte) :
    symbolicBehaviorWritesInside footprint behavior state := by
  intro byte member
  have byteMember : byte ∈ wordByteAddresses concreteAddress := by
    simpa only [symbolicWriteBytes, writesExact, List.flatMap_cons,
      List.flatMap_nil, List.append_nil, addressExact] using member
  exact inside byte byteMember

theorem addressRangeInSpan_containsWordBytes
    (span : Span) (address : Word)
    (range : addressRangeInSpan span address 4) :
    ∀ byte, byte ∈ wordByteAddresses address -> addressInSpan span byte := by
  intro byte member
  simp only [wordByteAddresses, List.mem_cons, List.not_mem_nil,
    or_false] at member
  rcases member with first | second | third | fourth
  · rw [first]
    simpa [word32] using range 0 (by omega)
  · rw [second]
    simpa [word32] using range 1 (by omega)
  · rw [third]
    simpa [word32] using range 2 (by omega)
  · rw [fourth]
    simpa [word32] using range 3 (by omega)

theorem symbolicWriteFootprint_complementDisjoint_of_writesInside
    (footprint : CandidateFootprint)
    (behavior : SymbolicBehavior) (state : MachineState)
    (inside : symbolicBehaviorWritesInside footprint behavior state) :
    CandidateFootprintsDisjoint (fun address => ¬ footprint address)
      (symbolicWriteFootprint behavior state).contains := by
  intro address outside changed
  apply outside
  apply inside address
  exact
    (mem_deduplicateWords address
      (symbolicWriteBytes behavior state)).mp changed

theorem runCheckedNativeOperationRunningTrace_memoryAgreesOn
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (domain : CandidateFootprint) (state : MachineState)
    (disjoint : forall edge,
      edge ∈ edges ->
      forall input,
        CandidateFootprintsDisjoint domain
          (symbolicWriteFootprint edge.replay.behavior input).contains) :
    MemoryAgreesOn domain
      (runCheckedNativeOperationRunningTrace edges state).memory
      state.memory := by
  induction edges generalizing state with
  | nil =>
      exact MemoryAgreesOn.refl domain state.memory
  | cons edge tail induction =>
      have headFrame := checkedNativeOperationRunningEdge_memoryAgreesOn
        edge domain state
        (disjoint edge (by simp) state)
      have tailDisjoint : forall memberEdge,
          memberEdge ∈ tail ->
          forall input,
            CandidateFootprintsDisjoint domain
              (symbolicWriteFootprint memberEdge.replay.behavior input).contains := by
        intro memberEdge member input
        exact disjoint memberEdge (by simp [member]) input
      have tailFrame := induction (edge.after state) tailDisjoint
      exact headFrame.trans tailFrame

/-- State-indexed footprint evidence for one exact running trace.  Unlike the
uniform certificate above, this follows the checked replay state and is
suitable for stack-relative writes whose concrete addresses are constrained
by an entry invariant. -/
def checkedNativeOperationRunningTraceFootprintsDisjointAt
    {candidate : ExactNativeWorldProgram} :
    List (CheckedNativeOperationRunningEdge candidate) ->
      CandidateFootprint -> MachineState -> Prop
  | [], _domain, _state => True
  | edge :: tail, domain, state =>
      CandidateFootprintsDisjoint domain
          (symbolicWriteFootprint edge.replay.behavior state).contains ∧
        checkedNativeOperationRunningTraceFootprintsDisjointAt
          tail domain (edge.after state)

/-- State-indexed dual of the disjointness certificate: each exact write is
classified inside one permitted footprint. -/
def checkedNativeOperationRunningTraceWritesInsideAt
    {candidate : ExactNativeWorldProgram} :
    List (CheckedNativeOperationRunningEdge candidate) ->
      CandidateFootprint -> MachineState -> Prop
  | [], _footprint, _state => True
  | edge :: tail, footprint, state =>
      symbolicBehaviorWritesInside footprint edge.replay.behavior state ∧
        checkedNativeOperationRunningTraceWritesInsideAt
          tail footprint (edge.after state)

theorem
    checkedNativeOperationRunningTraceFootprintsDisjointAt_of_writesInsideAt
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (footprint : CandidateFootprint) (state : MachineState)
    (inside :
      checkedNativeOperationRunningTraceWritesInsideAt
        edges footprint state) :
    checkedNativeOperationRunningTraceFootprintsDisjointAt edges
      (fun address => ¬ footprint address) state := by
  induction edges generalizing state with
  | nil => trivial
  | cons edge tail induction =>
      exact ⟨
        symbolicWriteFootprint_complementDisjoint_of_writesInside
          footprint edge.replay.behavior state inside.1,
        induction (edge.after state) inside.2⟩

theorem runCheckedNativeOperationRunningTrace_memoryAgreesOn_at
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (domain : CandidateFootprint) (state : MachineState)
    (disjoint :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        edges domain state) :
    MemoryAgreesOn domain
      (runCheckedNativeOperationRunningTrace edges state).memory
      state.memory := by
  induction edges generalizing state with
  | nil =>
      exact MemoryAgreesOn.refl domain state.memory
  | cons edge tail induction =>
      have headFrame :=
        checkedNativeOperationRunningEdge_memoryAgreesOn
          edge domain state disjoint.1
      have tailFrame := induction (edge.after state) disjoint.2
      exact headFrame.trans tailFrame

theorem checkedNativeOperationRunningEdge_after_x87Semantics
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) :
    (edge.after state).x87Semantics = state.x87Semantics := by
  rfl

theorem checkedNativeOperationStoppedEdge_after_x87Semantics
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) :
    (edge.after state).x87Semantics = state.x87Semantics := by
  rfl

theorem runCheckedNativeOperationRunningTrace_x87Semantics
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (state : MachineState) :
    (runCheckedNativeOperationRunningTrace edges state).x87Semantics =
      state.x87Semantics := by
  induction edges generalizing state with
  | nil => rfl
  | cons edge tail induction =>
      exact (induction (edge.after state)).trans
        (checkedNativeOperationRunningEdge_after_x87Semantics edge state)

def checkedNativeOperationBlockPreserves
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (domain : CandidateFootprint) : Prop :=
  forall state,
    MemoryAgreesOn domain
      (block.terminal.after (block.terminalState state)).memory
      state.memory

theorem checkedNativeOperationBlockPreserves_ofFootprints
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (domain : CandidateFootprint)
    (runningDisjoint : forall trace,
      block.running = some trace ->
      forall edge,
        edge ∈ trace.edges ->
        forall input,
          CandidateFootprintsDisjoint domain
            (symbolicWriteFootprint edge.replay.behavior input).contains)
    (terminalDisjoint : forall input,
      CandidateFootprintsDisjoint domain
        (block.terminal.cutpoint.postcondition.writeFootprint input).contains) :
    checkedNativeOperationBlockPreserves block domain := by
  intro state
  have runningFrame :
      MemoryAgreesOn domain (block.terminalState state).memory
        state.memory := by
    cases runningExact : block.running with
    | none =>
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          MemoryAgreesOn.refl domain state.memory
    | some trace =>
        have frame :=
          runCheckedNativeOperationRunningTrace_memoryAgreesOn
            trace.edges domain state
            (runningDisjoint trace runningExact)
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          frame
  have terminalFrame :=
    block.terminal.cutpoint.postcondition.stoppedMemoryFrame
      block.terminal.replay (block.terminalState state)
  have terminalProtected :
      MemoryAgreesOn domain
        (block.terminal.after (block.terminalState state)).memory
        (block.terminalState state).memory := by
    intro address member
    exact terminalFrame address
      (terminalDisjoint (block.terminalState state) address member)
  exact runningFrame.trans terminalProtected

/-- Dynamic disjointness evidence for exactly the state entering a checked
block.  The terminal footprint is evaluated after the checked running prefix,
so the certificate cannot silently reuse a stale stack or register value. -/
def checkedNativeOperationBlockFootprintsDisjointAt
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (domain : CandidateFootprint) (state : MachineState) : Prop :=
  (match block.running with
    | none => True
    | some trace =>
        checkedNativeOperationRunningTraceFootprintsDisjointAt
          trace.edges domain state) ∧
    CandidateFootprintsDisjoint domain
      (block.terminal.cutpoint.postcondition.writeFootprint
        (block.terminalState state)).contains

/-- Every exact write in a checked block is contained in one permitted
footprint.  The terminal transition is checked at the exact state produced by
the running prefix. -/
def checkedNativeOperationBlockWritesInsideAt
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (footprint : CandidateFootprint) (state : MachineState) : Prop :=
  (match block.running with
    | none => True
    | some trace =>
        checkedNativeOperationRunningTraceWritesInsideAt
          trace.edges footprint state) ∧
    symbolicBehaviorWritesInside footprint block.terminal.replay.behavior
      (block.terminalState state)

theorem checkedNativeOperationBlockFootprintsDisjointAt_of_writesInsideAt
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (footprint : CandidateFootprint) (state : MachineState)
    (inside :
      checkedNativeOperationBlockWritesInsideAt block footprint state) :
    checkedNativeOperationBlockFootprintsDisjointAt block
      (fun address => ¬ footprint address) state := by
  constructor
  · cases runningExact : block.running with
    | none => trivial
    | some trace =>
        apply
          checkedNativeOperationRunningTraceFootprintsDisjointAt_of_writesInsideAt
            trace.edges footprint state
        simpa [checkedNativeOperationBlockWritesInsideAt, runningExact] using
          inside.1
  · change
      CandidateFootprintsDisjoint (fun address => ¬ footprint address)
        (symbolicWriteFootprint block.terminal.replay.behavior
          (block.terminalState state)).contains
    exact symbolicWriteFootprint_complementDisjoint_of_writesInside
      footprint block.terminal.replay.behavior (block.terminalState state)
      inside.2

theorem checkedNativeOperationBlock_memoryAgreesOn_at
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (domain : CandidateFootprint) (state : MachineState)
    (disjoint :
      checkedNativeOperationBlockFootprintsDisjointAt block domain state) :
    MemoryAgreesOn domain
      (block.terminal.after (block.terminalState state)).memory
      state.memory := by
  have runningFrame :
      MemoryAgreesOn domain (block.terminalState state).memory
        state.memory := by
    cases runningExact : block.running with
    | none =>
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          MemoryAgreesOn.refl domain state.memory
    | some trace =>
        have frame :=
          runCheckedNativeOperationRunningTrace_memoryAgreesOn_at
            trace.edges domain state (by
              simpa [checkedNativeOperationBlockFootprintsDisjointAt,
                runningExact] using disjoint.1)
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          frame
  have terminalFrame :=
    block.terminal.cutpoint.postcondition.stoppedMemoryFrame
      block.terminal.replay (block.terminalState state)
  have terminalProtected :
      MemoryAgreesOn domain
        (block.terminal.after (block.terminalState state)).memory
        (block.terminalState state).memory := by
    intro address member
    exact terminalFrame address (disjoint.2 address member)
  exact runningFrame.trans terminalProtected

/-- A checked block whose exact writes are all inside `footprint` agrees with
its input memory everywhere outside that footprint. -/
theorem checkedNativeOperationBlock_memoryAgreesOutside_at
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (footprint : CandidateFootprint) (state : MachineState)
    (inside :
      checkedNativeOperationBlockWritesInsideAt block footprint state) :
    MemoryAgreesOutside footprint
      (block.terminal.after (block.terminalState state)).memory
      state.memory := by
  exact checkedNativeOperationBlock_memoryAgreesOn_at block
    (fun address => ¬ footprint address) state
    (checkedNativeOperationBlockFootprintsDisjointAt_of_writesInsideAt
      block footprint state inside)

theorem checkedNativeOperationBlock_after_x87Semantics
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) :
    (block.terminal.after (block.terminalState state)).x87Semantics =
      state.x87Semantics := by
  have running :
      (block.terminalState state).x87Semantics = state.x87Semantics := by
    cases runningExact : block.running with
    | none =>
        simp [CheckedNativeOperationBlock.terminalState, runningExact]
    | some trace =>
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          runCheckedNativeOperationRunningTrace_x87Semantics trace.edges state
  exact (checkedNativeOperationStoppedEdge_after_x87Semantics block.terminal
    (block.terminalState state)).trans running

def checkedNativeOperationRunningTracePreservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate)) : Prop :=
  ∀ edge, edge ∈ edges -> edge.replay.behavior.flagsBase = none

theorem runCheckedNativeOperationRunningTrace_preservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (state : MachineState)
    (preserves :
      checkedNativeOperationRunningTracePreservesDirectionFlag edges) :
    (runCheckedNativeOperationRunningTrace edges state).eflags.extractLsb'
        10 1 =
      state.eflags.extractLsb' 10 1 := by
  induction edges generalizing state with
  | nil => rfl
  | cons edge tail induction =>
      have edgePreserves : edge.replay.behavior.flagsBase = none :=
        preserves edge (by simp)
      have tailPreserves :
          checkedNativeOperationRunningTracePreservesDirectionFlag tail := by
        intro memberEdge member
        exact preserves memberEdge (by simp [member])
      exact (induction (edge.after state) tailPreserves).trans (by
        rw [CheckedNativeOperationRunningEdge.after_eflags_extract_df,
          edgePreserves]
        simpa only [Option.getD, inputEflagsExpression_eval])

def checkedNativeOperationBlockPreservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate) : Prop :=
  (match block.running with
    | none => True
    | some trace =>
        checkedNativeOperationRunningTracePreservesDirectionFlag trace.edges) ∧
    block.terminal.replay.behavior.flagsBase = none

theorem checkedNativeOperationBlock_preservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState)
    (preserves : checkedNativeOperationBlockPreservesDirectionFlag block) :
    (block.terminal.after (block.terminalState state)).eflags.extractLsb'
        10 1 =
      state.eflags.extractLsb' 10 1 := by
  have running :
      (block.terminalState state).eflags.extractLsb' 10 1 =
        state.eflags.extractLsb' 10 1 := by
    cases runningExact : block.running with
    | none =>
        simp [CheckedNativeOperationBlock.terminalState, runningExact]
    | some trace =>
        have tracePreserves :
            checkedNativeOperationRunningTracePreservesDirectionFlag
              trace.edges := by
          simpa [checkedNativeOperationBlockPreservesDirectionFlag,
            runningExact] using preserves.1
        simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
          runCheckedNativeOperationRunningTrace_preservesDirectionFlag
            trace.edges state tracePreserves
  calc
    (block.terminal.after
        (block.terminalState state)).eflags.extractLsb' 10 1 =
        (block.terminalState state).eflags.extractLsb' 10 1 := by
      rw [CheckedNativeOperationStoppedEdge.after_eflags_extract_df,
        preserves.2]
      simpa only [Option.getD, inputEflagsExpression_eval]
    _ = state.eflags.extractLsb' 10 1 := running

/-- Dynamic write-footprint obligations for a state-indexed route. Each
obligation is evaluated at the exact state produced by the preceding checked
block, including repeated visits through a bounded loop. -/
def checkedNativeOperationStateRouteFootprintsDisjointAt
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (domain : CandidateFootprint) : Prop :=
  match route with
  | .final block state _ _ _ _ _ _ =>
      checkedNativeOperationBlockFootprintsDisjointAt block domain state
  | .step source state _ _ _ _ _ _ _ _ tail =>
      checkedNativeOperationBlockFootprintsDisjointAt source domain state ∧
        checkedNativeOperationStateRouteFootprintsDisjointAt tail domain

theorem checkedNativeOperationStateRoute_memoryAgreesOn_at
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (domain : CandidateFootprint)
    (disjoint :
      checkedNativeOperationStateRouteFootprintsDisjointAt route domain) :
    MemoryAgreesOn domain
      (finalBlock.terminal.after
        (finalBlock.terminalState finalState)).memory
      sourceState.memory := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact checkedNativeOperationBlock_memoryAgreesOn_at
        block domain state disjoint
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      have sourceFrame :=
        checkedNativeOperationBlock_memoryAgreesOn_at source domain state
          disjoint.1
      have targetStateExact :=
        successor.targetStateExact
          (nativeOperationOutcomeAlwaysRunningLocal_statePreserving
            source.terminal.cutpoint.postcondition.outcome alwaysRunningLocal)
      have first :
          MemoryAgreesOn domain successor.targetState.memory state.memory := by
        rw [← targetStateExact]
        exact sourceFrame
      exact first.trans (induction disjoint.2)

/-- A route writes only inside `footprint` when its exact, state-indexed write
footprints are disjoint from the complement.  This is the form needed by
call-frame composition: stack probes, spills, and argument setup may update
different concrete addresses, but every update must remain in the checked
workspace. -/
def checkedNativeOperationStateRouteWritesInsideAt
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (footprint : CandidateFootprint) : Prop :=
  checkedNativeOperationStateRouteFootprintsDisjointAt route
    (fun address => ¬ footprint address)

theorem checkedNativeOperationStateRoute_memoryAgreesOutside_at
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (footprint : CandidateFootprint)
    (writesInside :
      checkedNativeOperationStateRouteWritesInsideAt route footprint) :
    MemoryAgreesOutside footprint
      (finalBlock.terminal.after
        (finalBlock.terminalState finalState)).memory
      sourceState.memory := by
  exact checkedNativeOperationStateRoute_memoryAgreesOn_at route
    (fun address => ¬ footprint address) writesInside

def checkedNativeOperationStateRoutePreservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
    Prop :=
  match route with
  | .final block _ _ _ _ _ _ _ =>
      checkedNativeOperationBlockPreservesDirectionFlag block
  | .step source _ _ _ _ _ _ _ _ _ tail =>
      checkedNativeOperationBlockPreservesDirectionFlag source ∧
        checkedNativeOperationStateRoutePreservesDirectionFlag tail

theorem checkedNativeOperationStateRoute_preservesDirectionFlag
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (preserves :
      checkedNativeOperationStateRoutePreservesDirectionFlag route) :
    (finalBlock.terminal.after
        (finalBlock.terminalState finalState)).eflags.extractLsb' 10 1 =
      sourceState.eflags.extractLsb' 10 1 := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact checkedNativeOperationBlock_preservesDirectionFlag
        block state preserves
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      have sourcePreserves :=
        checkedNativeOperationBlock_preservesDirectionFlag
          source state preserves.1
      have targetStateExact :=
        successor.targetStateExact
          (nativeOperationOutcomeAlwaysRunningLocal_statePreserving
            source.terminal.cutpoint.postcondition.outcome alwaysRunningLocal)
      have first :
          successor.targetState.eflags.extractLsb' 10 1 =
            state.eflags.extractLsb' 10 1 := by
        rw [← targetStateExact]
        exact sourcePreserves
      exact (induction preserves.2).trans first

theorem checkedNativeOperationPredicateBlockStep_memoryAgreesOn
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (domain : CandidateFootprint)
    (preserves : checkedNativeOperationBlockPreserves sourceBlock domain)
    (state : MachineState) :
    MemoryAgreesOn domain (step.targetState state).memory state.memory := by
  simpa [CheckedNativeOperationPredicateBlockStep.targetState] using
    preserves state

theorem checkedNativeOperationPredicateRoute_memoryAgreesOn
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (domain : CandidateFootprint)
    (preserves : forall block,
      block ∈ blocks -> checkedNativeOperationBlockPreserves block domain)
    (state : MachineState) :
    MemoryAgreesOn domain
      (runCheckedNativeOperationPredicateRoute route state).memory
      state.memory := by
  induction route generalizing state with
  | one sourceBlock targetBlock sourceInvariant targetInvariant step =>
      exact checkedNativeOperationPredicateBlockStep_memoryAgreesOn step domain
        (preserves sourceBlock step.sourceMember) state
  | cons sourceBlock middleBlock finalBlock sourceInvariant middleInvariant
      finalInvariant step tail induction =>
      have first :=
        checkedNativeOperationPredicateBlockStep_memoryAgreesOn step domain
        (preserves sourceBlock step.sourceMember) state
      have rest := induction (step.targetState state)
      exact first.trans rest

/-- State-indexed footprint evidence for a predicate route.  Each tail
certificate is checked at the exact state produced by the preceding block. -/
def checkedNativeOperationPredicateRouteFootprintsDisjointAt
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (domain : CandidateFootprint) : MachineState -> Prop
  | state =>
      match route with
      | .one sourceBlock _ _ _ _ =>
          checkedNativeOperationBlockFootprintsDisjointAt
            sourceBlock domain state
      | .cons sourceBlock _ _ _ _ _ step tail =>
          checkedNativeOperationBlockFootprintsDisjointAt
              sourceBlock domain state ∧
            checkedNativeOperationPredicateRouteFootprintsDisjointAt
              tail domain (step.targetState state)

theorem checkedNativeOperationPredicateRoute_memoryAgreesOn_at
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (domain : CandidateFootprint) (state : MachineState)
    (disjoint :
      checkedNativeOperationPredicateRouteFootprintsDisjointAt
        route domain state) :
    MemoryAgreesOn domain
      (runCheckedNativeOperationPredicateRoute route state).memory
      state.memory := by
  induction route generalizing state with
  | one sourceBlock targetBlock sourceInvariant targetInvariant step =>
      simpa [runCheckedNativeOperationPredicateRoute] using
        checkedNativeOperationBlock_memoryAgreesOn_at
          sourceBlock domain state disjoint
  | cons sourceBlock middleBlock finalBlock sourceInvariant middleInvariant
      finalInvariant step tail induction =>
      have first :=
        checkedNativeOperationBlock_memoryAgreesOn_at
          sourceBlock domain state disjoint.1
      have rest := induction (step.targetState state) disjoint.2
      exact first.trans rest

/-- Predicate-route analogue of
`checkedNativeOperationStateRouteWritesInsideAt`. -/
def checkedNativeOperationPredicateRouteWritesInsideAt
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (footprint : CandidateFootprint) (state : MachineState) : Prop :=
  checkedNativeOperationPredicateRouteFootprintsDisjointAt route
    (fun address => ¬ footprint address) state

theorem checkedNativeOperationPredicateRoute_memoryAgreesOutside_at
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (footprint : CandidateFootprint) (state : MachineState)
    (writesInside :
      checkedNativeOperationPredicateRouteWritesInsideAt
        route footprint state) :
    MemoryAgreesOutside footprint
      (runCheckedNativeOperationPredicateRoute route state).memory
      state.memory := by
  exact checkedNativeOperationPredicateRoute_memoryAgreesOn_at route
    (fun address => ¬ footprint address) state writesInside

theorem checkedNativeOperationPredicateRoute_x87Semantics
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (state : MachineState) :
    (runCheckedNativeOperationPredicateRoute route state).x87Semantics =
      state.x87Semantics := by
  induction route generalizing state with
  | one sourceBlock targetBlock sourceInvariant targetInvariant step =>
      simpa [runCheckedNativeOperationPredicateRoute] using
        checkedNativeOperationBlock_after_x87Semantics sourceBlock state
  | cons sourceBlock middleBlock finalBlock sourceInvariant middleInvariant
      finalInvariant step tail induction =>
      exact (induction (step.targetState state)).trans
        (checkedNativeOperationBlock_after_x87Semantics sourceBlock state)

#print axioms MemoryAgreesOn.trans
#print axioms MemoryAgreesOn.mono
#print axioms MemoryAgreesOn.candidateMemoryAgreesOnRepresentation
#print axioms checkedNativeOperationRunningEdge_memoryAgreesOn
#print axioms
  symbolicBehaviorWritesInside_of_writes_singleton
#print axioms addressRangeInSpan_containsWordBytes
#print axioms
  symbolicWriteFootprint_complementDisjoint_of_writesInside
#print axioms runCheckedNativeOperationRunningTrace_memoryAgreesOn
#print axioms runCheckedNativeOperationRunningTrace_memoryAgreesOn_at
#print axioms
  checkedNativeOperationRunningTraceFootprintsDisjointAt_of_writesInsideAt
#print axioms checkedNativeOperationRunningEdge_after_x87Semantics
#print axioms checkedNativeOperationStoppedEdge_after_x87Semantics
#print axioms runCheckedNativeOperationRunningTrace_x87Semantics
#print axioms checkedNativeOperationBlockPreserves_ofFootprints
#print axioms checkedNativeOperationBlock_memoryAgreesOn_at
#print axioms checkedNativeOperationBlock_memoryAgreesOutside_at
#print axioms checkedNativeOperationBlock_after_x87Semantics
#print axioms runCheckedNativeOperationRunningTrace_preservesDirectionFlag
#print axioms checkedNativeOperationBlock_preservesDirectionFlag
#print axioms checkedNativeOperationStateRoute_memoryAgreesOn_at
#print axioms checkedNativeOperationStateRoute_memoryAgreesOutside_at
#print axioms checkedNativeOperationStateRoute_preservesDirectionFlag
#print axioms checkedNativeOperationPredicateBlockStep_memoryAgreesOn
#print axioms checkedNativeOperationPredicateRoute_memoryAgreesOn
#print axioms checkedNativeOperationPredicateRoute_memoryAgreesOn_at
#print axioms checkedNativeOperationPredicateRoute_memoryAgreesOutside_at
#print axioms checkedNativeOperationPredicateRoute_x87Semantics

end StageA.Relational.InterpreterKernelOperationMemoryRoute
