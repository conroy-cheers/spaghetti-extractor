import StageA.RelationalInterpreterKernelBlock
import StageA.RelationalInterpreterKernelInvokeNative

namespace StageA.Relational.InterpreterKernelHelperPath

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelBlock
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterNativeWorld

/-!
Exact finite helper paths from a compiled helper entry to the next external
instruction. The strict profile accepts only a finite acyclic graph whose
decoded guards cover every direct successor. Exact execution is computed by the
native-world transition system; no caller supplies a final path.
-/

inductive HelperPathNodeKind where
  | internal
  | external
deriving Repr, DecidableEq

structure HelperPathNode where
  function : KernelFunction
  block : KernelBlock
  rank : Nat
  kind : HelperPathNodeKind
  targets : List Nat
deriving Repr, DecidableEq

def HelperPathNode.entryRva (node : HelperPathNode) : Nat :=
  node.block.entryRva

structure HelperPathGraph where
  helperEntryRva : Nat
  nodes : List HelperPathNode
deriving Repr, DecidableEq

def helperSameNatSet (left right : List Nat) : Bool :=
  decide left.Nodup && decide right.Nodup && left.length == right.length &&
    left.all right.contains

def HelperPathGraph.entries (graph : HelperPathGraph) : List Nat :=
  graph.nodes.map HelperPathNode.entryRva

def HelperPathGraph.nodeAt? (graph : HelperPathGraph)
    (entryRva : Nat) : Option HelperPathNode :=
  match graph.nodes.filter (fun node => node.entryRva == entryRva) with
  | [node] => some node
  | _ => none

def HelperPathNode.behavior? (pe : PE32) (imports : List PEImport)
    (node : HelperPathNode) : Option SymbolicBehavior :=
  node.block.symbolicBehavior? pe imports

def HelperPathNode.outcome? (pe : PE32) (imports : List PEImport)
    (node : HelperPathNode) : Option OutcomeExpr := do
  let behavior <- node.behavior? pe imports
  behavior.outcome

/-- Static successors whose selection is completely represented by the
reviewed symbolic outcome. Returns, indirect control, and external tails are
deliberately absent. -/
def strictHelperTargets? : OutcomeExpr -> Option (List Nat)
  | .jump target => some [target]
  | .branch _ taken fallthrough => some [taken, fallthrough].eraseDups
  | .call target continuation _ => some [target, continuation].eraseDups
  | .bulkCopy _ continuation => some [continuation]
  | .checkedContinue _ continuation => some [continuation]
  | .atomicCompareExchange _ _ _ continuation => some [continuation]
  | .returned _ | .externalCall .. | .externalJump ..
  | .indirectCall .. | .indirectJump _ => none

def HelperPathNode.externalChecked (pe : PE32) (imports : List PEImport)
    (node : HelperPathNode) : Bool :=
  match node.kind, node.outcome? pe imports,
      node.block.instructions.getLast? with
  | .external, some (.externalCall ..), some instruction =>
      node.targets.isEmpty &&
        instruction.rva + instruction.bytes.length <=
          node.function.span.stop
  | _, _, _ => false

def HelperPathNode.internalBaseChecked (node : HelperPathNode) : Bool :=
  node.kind == .internal && decide node.targets.Nodup

def HelperPathNode.membershipChecked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (node : HelperPathNode) : Bool :=
  program.functions.contains node.function &&
    node.function.blocks.contains node.block &&
    node.block.checked pe imports

def HelperPathGraph.targetRankDecreases (graph : HelperPathGraph)
    (node : HelperPathNode) (target : Nat) : Bool :=
  match graph.nodeAt? target with
  | some targetNode => targetNode.rank < node.rank
  | none => false

def HelperPathNode.strictInternalChecked
    (pe : PE32) (imports : List PEImport) (graph : HelperPathGraph)
    (node : HelperPathNode) : Bool :=
  node.internalBaseChecked &&
    match node.outcome? pe imports with
    | some outcome =>
        match strictHelperTargets? outcome with
        | some expected =>
            helperSameNatSet node.targets expected &&
              node.targets.all (graph.targetRankDecreases node)
        | none => false
    | none => false

def closeHelperPathEntries (graph : HelperPathGraph) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := reached.flatMap fun entry =>
        match graph.nodeAt? entry with
        | some node => node.targets
        | none => []
      closeHelperPathEntries graph fuel (reached ++ next).eraseDups

def HelperPathGraph.reachableEntries (graph : HelperPathGraph) : List Nat :=
  closeHelperPathEntries graph graph.nodes.length [graph.helperEntryRva]

def HelperPathGraph.baseChecked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (graph : HelperPathGraph) : Bool :=
  !graph.nodes.isEmpty &&
    decide graph.entries.Nodup &&
    graph.entries.contains graph.helperEntryRva &&
    graph.nodes.all (HelperPathNode.membershipChecked program pe imports) &&
    graph.nodes.all (fun node =>
      decide node.targets.Nodup &&
        node.targets.all graph.entries.contains &&
        match node.kind with
        | .internal => true
        | .external => node.externalChecked pe imports) &&
    graph.nodes.any (fun node => node.kind == .external) &&
    helperSameNatSet graph.entries graph.reachableEntries

/-- The strict checker establishes exact block membership, complete direct
guard successors, an external leaf, and a decreasing rank on every edge. -/
def HelperPathGraph.strictChecked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (graph : HelperPathGraph) : Bool :=
  graph.baseChecked program pe imports &&
    match graph.nodeAt? graph.helperEntryRva with
    | some entry =>
        entry.kind == .internal &&
          match entry.function.role with
          | .helper id => id == graph.helperEntryRva
          | _ => false
    | none => false
    &&
    graph.nodes.all fun node =>
      match node.kind with
      | .internal => node.strictInternalChecked pe imports graph
      | .external => node.externalChecked pe imports

def HelperPathNode.internalInstructionRvas
    (node : HelperPathNode) : List Nat :=
  match node.kind with
  | .internal => node.block.instructions.map (·.rva)
  | .external => node.block.instructions.dropLast.map (·.rva)

def HelperPathGraph.internalInstructionRvas
    (graph : HelperPathGraph) : List Nat :=
  graph.nodes.flatMap HelperPathNode.internalInstructionRvas

def HelperPathGraph.internalExecutionAllowed
    (graph : HelperPathGraph) : NativeWorldExecution -> Bool
  | .running rva _ _ _ _ _ _ =>
      graph.internalInstructionRvas.contains rva
  | _ => false

/-- Exact endpoint before the external instruction executes. The event index,
event history, call frames, and world must be the same as at helper entry. -/
structure HelperPathExternalBoundary
    (candidate : ExactNativeWorldProgram) (graph : HelperPathGraph)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (execution : NativeWorldExecution) where
  node : HelperPathNode
  nodeListed : node ∈ graph.nodes
  nodeExternal : node.kind = .external
  instruction : KernelInstruction
  instructionLast : node.block.instructions.getLast? = some instruction
  undefinedSlot : Nat
  state : MachineState
  calls : List NativeCallFrame
  imported : PEImport
  arguments : List Word
  continuationRva : Nat
  decodedAfter : MachineState
  executionExact : execution =
    .running instruction.rva undefinedSlot state calls eventIndex events world
  decodedExact : stepKernelPE32Instruction candidate.pe candidate.imports
    (.running instruction.rva undefinedSlot state) =
      .stopped (.externalCall imported arguments continuationRva) decodedAfter

def HelperPathEntryPrecondition :=
  MachineState -> List NativeCallFrame -> Nat -> List NativeExternalEvent ->
    RelationalWorld -> Prop

structure HelperPathReflectedNodeCertificate
    (pe : PE32) (imports : List PEImport) (graph : HelperPathGraph) where
  node : HelperPathNode
  nodeListed : node ∈ graph.nodes
  certificate : ReflectiveBlockCertificate pe imports node.block

structure HelperPathReflectiveInventory
    (pe : PE32) (imports : List PEImport) (graph : HelperPathGraph) where
  certificates : List (HelperPathReflectedNodeCertificate pe imports graph)
  covers : certificates.map (·.node) = graph.nodes

/-- One local segment has no submitted endpoint or observation list. Both are
computed by the exact candidate transition system. Zero fuel is admitted only
so an external instruction may itself be the entry of a terminal block. -/
structure ExactComputedHelperNodeSegment
    (candidate : ExactNativeWorldProgram) (graph : HelperPathGraph)
    (node : HelperPathNode) (undefinedSlot : Nat) (before : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) where
  nodeListed : node ∈ graph.nodes
  fuel : Nat
  silent :
    (runRelatedSteps candidate.transitionSystem fuel
      (.running node.entryRva undefinedSlot before calls eventIndex events
        world)).2 = []
  prefixesInsideNode : forall count, count < fuel ->
    match
      (runRelatedSteps candidate.transitionSystem count
        (.running node.entryRva undefinedSlot before calls eventIndex events
          world)).1.rva?
    with
    | some rva => node.internalInstructionRvas.contains rva
    | none => false

def ExactComputedHelperNodeSegment.after
    (segment : ExactComputedHelperNodeSegment candidate graph node undefinedSlot
      before calls eventIndex events world) : NativeWorldExecution :=
  (runRelatedSteps candidate.transitionSystem segment.fuel
    (.running node.entryRva undefinedSlot before calls eventIndex events
      world)).1

theorem ExactComputedHelperNodeSegment.runExact
    (segment : ExactComputedHelperNodeSegment candidate graph node undefinedSlot
      before calls eventIndex events world) :
    runRelatedSteps candidate.transitionSystem segment.fuel
      (.running node.entryRva undefinedSlot before calls eventIndex events
        world) = (segment.after, []) := by
  apply Prod.ext
  · rfl
  · exact segment.silent

/-- An internal local segment must end at one exact declared graph target.
The event history and relational world are unchanged; calls may add or remove
checked native frames. -/
structure HelperPathInternalBoundary
    (graph : HelperPathGraph) (source : HelperPathNode)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) (execution : NativeWorldExecution) where
  target : HelperPathNode
  targetListed : target ∈ graph.nodes
  targetDeclared : target.entryRva ∈ source.targets
  undefinedSlot : Nat
  state : MachineState
  calls : List NativeCallFrame
  executionExact : execution =
    .running target.entryRva undefinedSlot state calls eventIndex events world

/-- The local proof unit. Each value is one exact finite candidate execution
through a single reflected node. It either reaches the exact external
instruction or threads the complete machine/call/world state into one declared
successor. Internal progress is positive and decreases the supplied semantic
rank, so even explicitly-authorized cyclic graphs cannot stutter forever. -/
inductive ExactComputedHelperNodeProgress
    (candidate : ExactNativeWorldProgram) (graph : HelperPathGraph)
    (invariant : NativeWorldExecution -> Prop)
    (rank : NativeWorldExecution -> Nat)
    (node : HelperPathNode) (undefinedSlot : Nat) (before : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) : Type where
  | external
      (nodeExternal : node.kind = .external)
      (segment : ExactComputedHelperNodeSegment candidate graph node
        undefinedSlot before calls eventIndex events world)
      (boundary : HelperPathExternalBoundary candidate graph eventIndex events
        world segment.after)
      (boundaryNodeExact : boundary.node = node) :
      ExactComputedHelperNodeProgress candidate graph invariant rank node
        undefinedSlot before calls eventIndex events world
  | internal
      (nodeInternal : node.kind = .internal)
      (segment : ExactComputedHelperNodeSegment candidate graph node
        undefinedSlot before calls eventIndex events world)
      (positive : 0 < segment.fuel)
      (boundary : HelperPathInternalBoundary graph node eventIndex events world
        segment.after)
      (successorInvariant : invariant segment.after)
      (rankDecreases :
        rank segment.after <
          rank (.running node.entryRva undefinedSlot before calls eventIndex
            events world)) :
      ExactComputedHelperNodeProgress candidate graph invariant rank node
        undefinedSlot before calls eventIndex events world

/-- Per-node semantic authority. The reflective inventory covers exactly the
static graph. `progress` is universal over concrete candidate states but proves
only one node at a time; it cannot submit a whole helper path or endpoint. -/
structure HelperPathLocalProgressCertificate
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (graph : HelperPathGraph)
    (precondition : HelperPathEntryPrecondition) where
  reflected :
    HelperPathReflectiveInventory candidate.pe candidate.imports graph
  entryNode : HelperPathNode
  entryListed : entryNode ∈ graph.nodes
  entryExact : entryNode.entryRva = graph.helperEntryRva
  entryInternal : entryNode.kind = .internal
  invariant : NativeWorldExecution -> Prop
  rank : NativeWorldExecution -> Nat
  establish : forall before calls eventIndex events world,
    precondition before calls eventIndex events world ->
      invariant
        (.running graph.helperEntryRva 0 before calls eventIndex events world)
  progress : forall node,
    node ∈ graph.nodes ->
    forall undefinedSlot before calls eventIndex events world,
    invariant
      (.running node.entryRva undefinedSlot before calls eventIndex events
        world) ->
    Nonempty (ExactComputedHelperNodeProgress candidate graph invariant rank
      node undefinedSlot before calls eventIndex events world)

/-- Exceptional control cannot be enabled by metadata. The explicit authority
is indexed by the exact local certificate whose invariant and ranking function
make the otherwise cyclic or non-reflective target graph well founded. -/
structure HelperPathInvariantRankingAuthority
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (graph : HelperPathGraph)
    (precondition : HelperPathEntryPrecondition)
    (localCertificate : HelperPathLocalProgressCertificate program candidate graph
      precondition) where
  baseChecked :
    graph.baseChecked program candidate.pe candidate.imports = true

/-- A traversal is built only from local computed segments. The terminal
constructor reaches an exact decoded external boundary. The internal
constructor carries the complete successor state into the recursively composed
tail. -/
inductive ExactComputedHelperPathTraversal
    (candidate : ExactNativeWorldProgram) (graph : HelperPathGraph)
    (invariant : NativeWorldExecution -> Prop)
    (rank : NativeWorldExecution -> Nat)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    HelperPathNode -> Nat -> MachineState -> List NativeCallFrame -> Type where
  | terminal
      {node : HelperPathNode} {undefinedSlot : Nat} {before : MachineState}
      {calls : List NativeCallFrame}
      (nodeExternal : node.kind = .external)
      (segment : ExactComputedHelperNodeSegment candidate graph node
        undefinedSlot before calls eventIndex events world)
      (boundary : HelperPathExternalBoundary candidate graph eventIndex events
        world segment.after)
      (boundaryNodeExact : boundary.node = node) :
      ExactComputedHelperPathTraversal candidate graph invariant rank eventIndex
        events world node undefinedSlot before calls
  | advance
      {node : HelperPathNode} {undefinedSlot : Nat} {before : MachineState}
      {calls : List NativeCallFrame}
      (nodeInternal : node.kind = .internal)
      (segment : ExactComputedHelperNodeSegment candidate graph node
        undefinedSlot before calls eventIndex events world)
      (positive : 0 < segment.fuel)
      (boundary : HelperPathInternalBoundary graph node eventIndex events world
        segment.after)
      (successorInvariant : invariant segment.after)
      (rankDecreases :
        rank segment.after <
          rank (.running node.entryRva undefinedSlot before calls eventIndex
            events world))
      (tail : ExactComputedHelperPathTraversal candidate graph invariant rank
        eventIndex events world boundary.target boundary.undefinedSlot
        boundary.state boundary.calls) :
      ExactComputedHelperPathTraversal candidate graph invariant rank eventIndex
        events world node undefinedSlot before calls

def ExactComputedHelperPathTraversal.fuel :
    ExactComputedHelperPathTraversal candidate graph invariant rank eventIndex
      events world node undefinedSlot before calls -> Nat
  | .terminal _ segment _ _ => segment.fuel
  | .advance _ segment _ _ _ _ tail => segment.fuel + tail.fuel

def ExactComputedHelperPathTraversal.after :
    (traversal : ExactComputedHelperPathTraversal candidate graph invariant rank
      eventIndex events world node undefinedSlot before calls) ->
      NativeWorldExecution
  | .terminal _ segment _ _ => segment.after
  | .advance _ _ _ _ _ _ tail => tail.after

def ExactComputedHelperPathTraversal.boundary :
    (traversal : ExactComputedHelperPathTraversal candidate graph invariant rank
      eventIndex events world node undefinedSlot before calls) ->
      HelperPathExternalBoundary candidate graph eventIndex events world
        traversal.after
  | .terminal _ _ boundary _ => boundary
  | .advance _ _ _ _ _ _ tail => tail.boundary

theorem ExactComputedHelperPathTraversal.runExact
    (traversal : ExactComputedHelperPathTraversal candidate graph invariant rank
      eventIndex events world node undefinedSlot before calls) :
    runRelatedSteps candidate.transitionSystem traversal.fuel
      (.running node.entryRva undefinedSlot before calls eventIndex events
        world) = (traversal.after, []) := by
  induction traversal with
  | terminal nodeExternal segment boundary boundaryNodeExact =>
      exact segment.runExact
  | advance nodeInternal segment positive boundary successorInvariant
      rankDecreases tail induction =>
      rw [ExactComputedHelperPathTraversal.fuel, runRelatedSteps_add,
        segment.runExact]
      simp only [List.nil_append]
      change runRelatedSteps candidate.transitionSystem tail.fuel segment.after =
        (tail.after, [])
      calc
        runRelatedSteps candidate.transitionSystem tail.fuel segment.after =
            runRelatedSteps candidate.transitionSystem tail.fuel
              (.running boundary.target.entryRva boundary.undefinedSlot
                boundary.state boundary.calls eventIndex events world) :=
          congrArg (runRelatedSteps candidate.transitionSystem tail.fuel)
            boundary.executionExact
        _ = (tail.after, []) := induction

theorem ExactComputedHelperPathTraversal.positive_of_internal
    (traversal : ExactComputedHelperPathTraversal candidate graph invariant rank
      eventIndex events world node undefinedSlot before calls)
    (internal : node.kind = .internal) :
    0 < traversal.fuel := by
  cases traversal with
  | terminal nodeExternal =>
      rw [nodeExternal] at internal
      contradiction
  | advance _ segment positive =>
      exact Nat.add_pos_left positive _

private noncomputable def composeHelperPathFromNode
    (localCertificate : HelperPathLocalProgressCertificate program candidate graph
      precondition)
    (node : HelperPathNode) (nodeListed : node ∈ graph.nodes)
    (undefinedSlot : Nat) (before : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (holds : localCertificate.invariant
      (.running node.entryRva undefinedSlot before calls eventIndex events
        world)) :
    Nonempty (ExactComputedHelperPathTraversal candidate graph
      localCertificate.invariant localCertificate.rank eventIndex events world
      node undefinedSlot before calls) := by
  obtain ⟨progress⟩ :=
    localCertificate.progress node nodeListed undefinedSlot before calls
      eventIndex events world holds
  cases progress with
  | external nodeExternal segment boundary boundaryNodeExact =>
      exact ⟨.terminal nodeExternal segment boundary boundaryNodeExact⟩
  | internal nodeInternal segment positive boundary successorInvariant
      rankDecreases =>
      have nextInvariant : localCertificate.invariant
          (.running boundary.target.entryRva boundary.undefinedSlot
            boundary.state boundary.calls eventIndex events world) := by
        rw [← boundary.executionExact]
        exact successorInvariant
      obtain ⟨tail⟩ :=
        composeHelperPathFromNode localCertificate boundary.target
          boundary.targetListed boundary.undefinedSlot boundary.state
          boundary.calls eventIndex events world nextInvariant
      exact ⟨.advance nodeInternal segment positive boundary successorInvariant
        rankDecreases tail⟩
termination_by
  localCertificate.rank
    (.running node.entryRva undefinedSlot before calls eventIndex events world)
decreasing_by
  simpa [boundary.executionExact] using rankDecreases

/-- The universally composed execution is a derived traversal from the helper
entry to its exact external boundary. No final path, endpoint, or whole-helper
execution is accepted as a certificate field. -/
structure ExactComputedHelperPathExecution
    (candidate : ExactNativeWorldProgram) (graph : HelperPathGraph)
    (before : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) where
  invariant : NativeWorldExecution -> Prop
  rank : NativeWorldExecution -> Nat
  entryNode : HelperPathNode
  entryListed : entryNode ∈ graph.nodes
  entryExact : entryNode.entryRva = graph.helperEntryRva
  entryInternal : entryNode.kind = .internal
  traversal : ExactComputedHelperPathTraversal candidate graph invariant rank
    eventIndex events world entryNode 0 before calls

def ExactComputedHelperPathExecution.boundary
    (execution : ExactComputedHelperPathExecution candidate graph before calls
      eventIndex events world) :
    HelperPathExternalBoundary candidate graph eventIndex events world
      execution.traversal.after :=
  execution.traversal.boundary

theorem ExactComputedHelperPathExecution.pathToBoundary
    (execution : ExactComputedHelperPathExecution candidate graph before calls
      eventIndex events world) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running graph.helperEntryRva 0 before calls eventIndex events world) []
      (.running execution.boundary.instruction.rva
        execution.boundary.undefinedSlot execution.boundary.state
        execution.boundary.calls eventIndex events world) := by
  refine ⟨execution.traversal.fuel,
    execution.traversal.positive_of_internal execution.entryInternal, ?_⟩
  rw [← execution.entryExact, execution.traversal.runExact]
  exact congrArg (fun after => (after, []))
    execution.boundary.executionExact

structure UniversalHelperPathExecutionCertificate
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (graph : HelperPathGraph) (precondition : HelperPathEntryPrecondition) where
  localCertificate :
    HelperPathLocalProgressCertificate program candidate graph precondition
  control :
    graph.strictChecked program candidate.pe candidate.imports = true \/
      Nonempty (HelperPathInvariantRankingAuthority program candidate graph
        precondition localCertificate)

theorem UniversalHelperPathExecutionCertificate.execute
    (certificate : UniversalHelperPathExecutionCertificate program candidate
      graph precondition)
    (holds : precondition before calls eventIndex events world) :
    Nonempty (ExactComputedHelperPathExecution candidate graph before calls
      eventIndex events world) := by
  have entryInvariant : certificate.localCertificate.invariant
      (.running certificate.localCertificate.entryNode.entryRva 0 before calls eventIndex
        events world) := by
    rw [certificate.localCertificate.entryExact]
    exact certificate.localCertificate.establish before calls eventIndex events
      world holds
  obtain ⟨traversal⟩ :=
    composeHelperPathFromNode certificate.localCertificate
      certificate.localCertificate.entryNode
      certificate.localCertificate.entryListed 0 before calls eventIndex events
      world entryInvariant
  exact ⟨{
    invariant := certificate.localCertificate.invariant
    rank := certificate.localCertificate.rank
    entryNode := certificate.localCertificate.entryNode
    entryListed := certificate.localCertificate.entryListed
    entryExact := certificate.localCertificate.entryExact
    entryInternal := certificate.localCertificate.entryInternal
    traversal
  }⟩

#print axioms ExactComputedHelperPathTraversal.runExact
#print axioms ExactComputedHelperPathExecution.pathToBoundary
#print axioms UniversalHelperPathExecutionCertificate.execute

end StageA.Relational.InterpreterKernelHelperPath
