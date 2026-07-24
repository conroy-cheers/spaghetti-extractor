import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterKernelLoop

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

/-! Exact CFG certificates and semantic induction obligations for loops in a
compiled Stage B interpreter kernel.  The Boolean layer checks only finite
graph facts.  Invariants and ranking arguments remain propositions and cannot
be manufactured by generated data. -/

structure KernelCFGEdge where
  source : Nat
  target : Nat
deriving Repr, DecidableEq

def listAt? {Value : Type} : List Value -> Nat -> Option Value
  | [], _ => none
  | value :: _, 0 => some value
  | _ :: tail, index + 1 => listAt? tail index

def localEdges (function : KernelFunction) : List KernelCFGEdge :=
  (function.blocks.flatMap fun block =>
    block.successors.filterMap fun target =>
      if function.blockEntries.contains target then
        some { source := block.entryRva, target }
      else none).eraseDups

def localPredecessors (function : KernelFunction)
    (entry : Nat) : List Nat :=
  (localEdges function |>.filterMap fun edge =>
    if edge.target == entry && function.reachableEntries.contains edge.source then
      some edge.source
    else none).eraseDups

def closeEntriesAvoiding (function : KernelFunction) (forbidden : Nat) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := reached.flatMap fun entry =>
        function.localSuccessors entry |>.filter (· != forbidden)
      closeEntriesAvoiding function forbidden fuel (reached ++ next).eraseDups

def reachableEntriesAvoiding (function : KernelFunction)
    (forbidden : Nat) : List Nat :=
  if function.span.start == forbidden then [] else
    closeEntriesAvoiding function forbidden function.blocks.length
      [function.span.start]

def dominates (function : KernelFunction)
    (dominator entry : Nat) : Bool :=
  function.reachableEntries.contains entry &&
    (dominator == function.span.start ||
      !(reachableEntriesAvoiding function dominator).contains entry)

def exactBackEdges (function : KernelFunction) : List KernelCFGEdge :=
  localEdges function |>.filter fun edge => dominates function edge.target edge.source

def reachableFrom (function : KernelFunction) (entry : Nat) : List Nat :=
  closeKernelEntries function function.blocks.length [entry]

def cyclicEdges (function : KernelFunction) : List KernelCFGEdge :=
  localEdges function |>.filter fun edge =>
    function.reachableEntries.contains edge.source &&
      (reachableFrom function edge.target).contains edge.source

def closeLoopPredecessors (function : KernelFunction) (header : Nat) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := (reached.filter (· != header)).flatMap
        (localPredecessors function)
      closeLoopPredecessors function header fuel (reached ++ next).eraseDups

def naturalLoopBody (function : KernelFunction)
    (edge : KernelCFGEdge) : List Nat :=
  closeLoopPredecessors function edge.target function.blocks.length
    [edge.target, edge.source]

def sameNatSet (left right : List Nat) : Bool :=
  decide left.Nodup && decide right.Nodup && left.length == right.length &&
    left.all right.contains

def sameEdgeSet (left right : List KernelCFGEdge) : Bool :=
  decide left.Nodup && decide right.Nodup && left.length == right.length &&
    left.all right.contains

structure KernelLoopShapeCertificate where
  headerRva : Nat
  latchRva : Nat
  bodyEntries : List Nat
deriving Repr, DecidableEq

def KernelLoopShapeCertificate.backEdge
    (certificate : KernelLoopShapeCertificate) : KernelCFGEdge :=
  { source := certificate.latchRva, target := certificate.headerRva }

def KernelLoopShapeCertificate.entryEdges (function : KernelFunction)
    (certificate : KernelLoopShapeCertificate) : List KernelCFGEdge :=
  localEdges function |>.filter fun edge =>
    !certificate.bodyEntries.contains edge.source &&
      certificate.bodyEntries.contains edge.target

def KernelLoopShapeCertificate.internalEdges (function : KernelFunction)
    (certificate : KernelLoopShapeCertificate) : List KernelCFGEdge :=
  localEdges function |>.filter fun edge =>
    certificate.bodyEntries.contains edge.source &&
      certificate.bodyEntries.contains edge.target

def KernelLoopShapeCertificate.exitEdges (function : KernelFunction)
    (certificate : KernelLoopShapeCertificate) : List KernelCFGEdge :=
  localEdges function |>.filter fun edge =>
    certificate.bodyEntries.contains edge.source &&
      !certificate.bodyEntries.contains edge.target

def closeEntriesInside (function : KernelFunction) (body : List Nat) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := reached.flatMap fun entry =>
        function.localSuccessors entry |>.filter body.contains
      closeEntriesInside function body fuel (reached ++ next).eraseDups

def KernelLoopShapeCertificate.bodyReachable (function : KernelFunction)
    (certificate : KernelLoopShapeCertificate) : List Nat :=
  closeEntriesInside function certificate.bodyEntries function.blocks.length
    [certificate.headerRva]

def KernelLoopShapeCertificate.checked (function : KernelFunction)
    (certificate : KernelLoopShapeCertificate) : Bool :=
  !certificate.bodyEntries.isEmpty && decide certificate.bodyEntries.Nodup &&
    (exactBackEdges function).contains certificate.backEdge &&
    sameNatSet certificate.bodyEntries
      (naturalLoopBody function certificate.backEdge) &&
    sameNatSet certificate.bodyEntries
      (certificate.bodyReachable function) &&
    (certificate.entryEdges function).all
      (fun edge => edge.target == certificate.headerRva)

structure KernelFunctionLoopCertificate where
  functionIndex : Nat
  functionEntryRva : Nat
  loops : List KernelLoopShapeCertificate
deriving Repr, DecidableEq

def KernelFunctionLoopCertificate.checked (program : CompiledKernelProgram)
    (certificate : KernelFunctionLoopCertificate) : Bool :=
  match listAt? program.functions certificate.functionIndex with
  | none => false
  | some function =>
      function.span.start == certificate.functionEntryRva &&
        !certificate.loops.isEmpty &&
        decide (certificate.loops.map (·.backEdge)).Nodup &&
        certificate.loops.all (·.checked function) &&
        sameEdgeSet (certificate.loops.map (·.backEdge)) (exactBackEdges function) &&
        (cyclicEdges function).all fun edge =>
          certificate.loops.any fun loop =>
            loop.bodyEntries.contains edge.source &&
              loop.bodyEntries.contains edge.target

def functionIndicesWithCycles : Nat -> List KernelFunction -> List Nat
  | _, [] => []
  | index, function :: tail =>
      let rest := functionIndicesWithCycles (index + 1) tail
      if (cyclicEdges function).isEmpty then rest else index :: rest

structure KernelLoopInventory where
  functions : List KernelFunctionLoopCertificate
deriving Repr, DecidableEq

def KernelLoopInventory.checked (program : CompiledKernelProgram)
    (inventory : KernelLoopInventory) : Bool :=
  decide (inventory.functions.map (·.functionIndex)).Nodup &&
    inventory.functions.all (·.checked program) &&
    sameNatSet (inventory.functions.map (·.functionIndex))
      (functionIndicesWithCycles 0 program.functions)

def executionAtRva : NativeExecution -> Nat -> Prop
  | .running rva _ _ _ _ _, expected => rva = expected
  | _, _ => False

inductive KernelIndirectControlKind where
  | call
  | jump
deriving Repr, DecidableEq

def indirectControlKind? (pe : PE32)
    (instruction : KernelInstruction) : Option KernelIndirectControlKind := do
  let decoded <- instruction.decode? pe
  match decoded.instruction with
  | .callIndirect _ => some .call
  | .jumpIndirect _ => some .jump
  | _ => none

def compiledKernelInstructions (program : CompiledKernelProgram) :
    List KernelInstruction :=
  program.functions.flatMap fun function =>
    function.blocks.flatMap (·.instructions)

def compiledKernelInstructionsAt (program : CompiledKernelProgram)
    (rva : Nat) : List KernelInstruction :=
  compiledKernelInstructions program |>.filter (·.rva == rva)

def collectIndirectControlRvas? (pe : PE32) :
    List KernelInstruction -> Option (List Nat)
  | [] => some []
  | instruction :: tail => do
      let decoded <- instruction.decode? pe
      let rest <- collectIndirectControlRvas? pe tail
      match decoded.instruction with
      | .callIndirect _ | .jumpIndirect _ => some (instruction.rva :: rest)
      | _ => some rest

structure KernelIndirectTargetClassifier where
  siteRva : Nat
  kind : KernelIndirectControlKind
  targetRvas : List Nat
deriving Repr, DecidableEq

def KernelIndirectTargetClassifier.checked
    (classifier : KernelIndirectTargetClassifier)
    (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) : Bool :=
  !classifier.targetRvas.isEmpty && decide classifier.targetRvas.Nodup &&
    classifier.targetRvas.all program.blockEntries.contains &&
    match compiledKernelInstructionsAt program classifier.siteRva with
    | [instruction] =>
        instruction.checked pe imports &&
          indirectControlKind? pe instruction == some classifier.kind
    | _ => false

structure KernelIndirectTargetInventory where
  classifiers : List KernelIndirectTargetClassifier
deriving Repr, DecidableEq

def KernelIndirectTargetInventory.checked
    (inventory : KernelIndirectTargetInventory)
    (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) : Bool :=
  decide (inventory.classifiers.map (·.siteRva)).Nodup &&
    inventory.classifiers.all (·.checked program pe imports) &&
    match collectIndirectControlRvas? pe (compiledKernelInstructions program) with
    | none => false
    | some indirectRvas =>
        sameNatSet (inventory.classifiers.map (·.siteRva)) indirectRvas

def KernelIndirectTargetInventory.allowsRva
    (inventory : KernelIndirectTargetInventory)
    (siteRva : Nat) (kind : KernelIndirectControlKind)
    (targetRva : Nat) : Bool :=
  inventory.classifiers.any fun classifier =>
    classifier.siteRva == siteRva && classifier.kind == kind &&
      classifier.targetRvas.contains targetRva

def programBlockAt? (program : CompiledKernelProgram)
    (entryRva : Nat) : Option KernelBlock :=
  match program.functions.flatMap (·.blocks) |>.filter (·.entryRva == entryRva) with
  | [block] => some block
  | _ => none

inductive KernelCFGEdgeKind where
  | direct
  | internalCall (continuationRva returnAddress : Nat)
  | internalReturn
  | indirectCall (siteRva continuationRva returnAddress : Nat)
  | indirectJump (siteRva : Nat)
  | externalContinuation
deriving Repr, DecidableEq

def KernelCFGEdgeKind.checked (kind : KernelCFGEdgeKind)
    (edge : KernelCFGEdge) (program : CompiledKernelProgram) (pe : PE32)
    (targets : KernelIndirectTargetInventory) : Bool :=
  match programBlockAt? program edge.source with
  | none => false
  | some block =>
      match kind with
      | .direct =>
          block.successors.contains edge.target &&
            program.blockEntries.contains edge.target
      | .internalCall continuationRva returnAddress =>
          block.successors.contains edge.target &&
            program.blockEntries.contains edge.target &&
            block.successors.contains continuationRva &&
            program.blockEntries.contains continuationRva &&
            returnAddress == pe.imageBase + continuationRva
      | .internalReturn => program.blockEntries.contains edge.target
      | .indirectCall siteRva continuationRva returnAddress =>
          block.instructions.getLast?.map (·.rva) == some siteRva &&
            block.successors.contains continuationRva &&
            targets.allowsRva siteRva .call edge.target &&
            returnAddress == pe.imageBase + continuationRva
      | .indirectJump siteRva =>
          block.instructions.getLast?.map (·.rva) == some siteRva &&
            targets.allowsRva siteRva .jump edge.target
      | .externalContinuation =>
          block.successors.contains edge.target &&
            program.blockEntries.contains edge.target

def executionCalls? : NativeExecution -> Option (List NativeCallFrame)
  | .running _ _ _ calls _ _ => some calls
  | _ => none

def executionEventIndex? : NativeExecution -> Option Nat
  | .running _ _ _ _ eventIndex _ => some eventIndex
  | _ => none

def executionEvents? : NativeExecution -> Option (List NativeExternalEvent)
  | .running _ _ _ _ _ events => some events
  | _ => none

def KernelCFGEdgeKind.Holds (kind : KernelCFGEdgeKind)
    (edge : KernelCFGEdge) (before after : NativeExecution) : Prop :=
  executionAtRva before edge.source ∧ executionAtRva after edge.target ∧
    match kind with
    | .direct | .indirectJump _ =>
        executionCalls? after = executionCalls? before ∧
          executionEventIndex? after = executionEventIndex? before ∧
          executionEvents? after = executionEvents? before
    | .internalCall continuationRva returnAddress
    | .indirectCall _ continuationRva returnAddress =>
        ∃ calls eventIndex events,
          executionCalls? before = some calls ∧
          executionCalls? after = some
            ({ continuationRva, returnAddress := BitVec.ofNat 32 returnAddress } :: calls) ∧
          executionEventIndex? before = some eventIndex ∧
          executionEventIndex? after = some eventIndex ∧
          executionEvents? before = some events ∧ executionEvents? after = some events
    | .internalReturn =>
        ∃ frame calls eventIndex events,
          frame.continuationRva = edge.target ∧
          executionCalls? before = some (frame :: calls) ∧
          executionCalls? after = some calls ∧
          executionEventIndex? before = some eventIndex ∧
          executionEventIndex? after = some eventIndex ∧
          executionEvents? before = some events ∧ executionEvents? after = some events
    | .externalContinuation =>
        ∃ calls eventIndex beforeEvents afterEvents,
          executionCalls? before = some calls ∧ executionCalls? after = some calls ∧
          executionEventIndex? before = some eventIndex ∧
          executionEventIndex? after = some (eventIndex + 1) ∧
          executionEvents? before = some beforeEvents ∧
          executionEvents? after = some afterEvents ∧
          beforeEvents.length + 1 = afterEvents.length

/-! A semantic loop edge is a nonempty execution in the exact PE machine from
one checked CFG cutpoint to the next.  Calls may introduce nested native call
frames; the relation therefore ranges over `NativeExecution`, not a flat stack
window. -/
def ExactKernelEdgeTransition (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (edge : KernelCFGEdge)
    (before after : NativeExecution) : Prop :=
  executionAtRva before edge.source ∧ executionAtRva after edge.target ∧
    ∃ first, stepNativeExecution pe imports environment before = first ∧
      NativeSteps pe imports environment first after

inductive NativeStepsN (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) :
    Nat -> NativeExecution -> NativeExecution -> Prop
  | zero (state) : NativeStepsN pe imports environment 0 state state
  | succ (count before middle after) :
      stepNativeExecution pe imports environment before = middle ->
      NativeStepsN pe imports environment count middle after ->
      NativeStepsN pe imports environment (count + 1) before after

theorem NativeStepsN.toNativeSteps {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {count : Nat}
    {before after : NativeExecution}
    (steps : NativeStepsN pe imports environment count before after) :
    NativeSteps pe imports environment before after := by
  induction steps with
  | zero => exact NativeSteps.refl _
  | succ count before middle after stepped _ induction =>
      exact NativeSteps.tail before middle after stepped induction

/-! `ExactKernelBlockRun` is the local-to-global bridge.  Membership and
symbolic soundness refer to the checked submitted block, while `exactSteps`
records the same number of exact PE machine steps as submitted instructions.
The explicit nonempty decomposition prevents a zero-step edge certificate. -/
structure ExactKernelBlockRun (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (before after : NativeExecution) where
  function : KernelFunction
  block : KernelBlock
  functionListed : function ∈ program.functions
  blockListed : block ∈ function.blocks
  blockChecked : block.checked pe imports = true
  blockSound : block.SymbolicExecutionSound pe imports
  beforeAtEntry : executionAtRva before block.entryRva
  exactSteps : NativeStepsN pe imports environment block.instructions.length
    before after
  nonemptyExecution : ∃ first,
    stepNativeExecution pe imports environment before = first ∧
      NativeSteps pe imports environment first after

theorem ExactKernelBlockRun.nativeSteps
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {before after : NativeExecution}
    (run : ExactKernelBlockRun program pe imports environment before after) :
    NativeSteps pe imports environment before after :=
  run.exactSteps.toNativeSteps

structure ExactKernelEdgeStep (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (targets : KernelIndirectTargetInventory)
    (before after : NativeExecution) where
  run : ExactKernelBlockRun program pe imports environment before after
  edge : KernelCFGEdge
  kind : KernelCFGEdgeKind
  sourceMatches : edge.source = run.block.entryRva
  afterAtTarget : executionAtRva after edge.target
  kindChecked : kind.checked edge program pe targets = true
  kindHolds : kind.Holds edge before after

theorem ExactKernelEdgeStep.nativeSteps
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {before after : NativeExecution}
    (step : ExactKernelEdgeStep program pe imports environment targets before after) :
    NativeSteps pe imports environment before after :=
  step.run.nativeSteps

theorem ExactKernelEdgeStep.edgeTransition
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {before after : NativeExecution}
    (step : ExactKernelEdgeStep program pe imports environment targets before after) :
    ExactKernelEdgeTransition pe imports environment step.edge before after := by
  refine ⟨?_, step.afterAtTarget, step.run.nonemptyExecution⟩
  rw [step.sourceMatches]
  exact step.run.beforeAtEntry

def TerminalNativeExecution : NativeExecution -> Prop
  | .running .. => False
  | .returned .. | .fault | .unsupportedIndirect .. => True

structure ExactKernelTerminalStep (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (before after : NativeExecution) where
  run : ExactKernelBlockRun program pe imports environment before after
  terminal : TerminalNativeExecution after

inductive ExactKernelCFGExecution (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (targets : KernelIndirectTargetInventory) :
    NativeExecution -> NativeExecution -> Prop
  | refl (state) :
      ExactKernelCFGExecution program pe imports environment targets state state
  | edge (before middle after) :
      ExactKernelEdgeStep program pe imports environment targets before middle ->
      ExactKernelCFGExecution program pe imports environment targets middle after ->
      ExactKernelCFGExecution program pe imports environment targets before after
  | terminal (before after) :
      ExactKernelTerminalStep program pe imports environment before after ->
      ExactKernelCFGExecution program pe imports environment targets before after

theorem ExactKernelCFGExecution.nativeSteps
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {before after : NativeExecution}
    (execution : ExactKernelCFGExecution program pe imports environment targets
      before after) :
    NativeSteps pe imports environment before after := by
  induction execution with
  | refl => exact NativeSteps.refl _
  | edge before middle after step _ induction =>
      exact step.nativeSteps.trans induction
  | terminal before after step => exact step.run.nativeSteps

structure KernelLoopContract where
  headerPrecondition : NativeExecution -> Prop
  entryPrecondition : KernelCFGEdge -> NativeExecution -> Prop
  invariant : Nat -> NativeExecution -> Prop
  exitPostcondition : KernelCFGEdge -> NativeExecution -> NativeExecution -> Prop
  rank : Nat -> NativeExecution -> Nat

def KernelLoopContract.RankRelation (contract : KernelLoopContract)
    (next current : Nat × NativeExecution) : Prop :=
  contract.rank next.1 next.2 < contract.rank current.1 current.2

theorem KernelLoopContract.rankRelation_wellFounded
    (contract : KernelLoopContract) :
    WellFounded contract.RankRelation :=
  by
    unfold KernelLoopContract.RankRelation
    exact InvImage.wf
      (fun item : Nat × NativeExecution => contract.rank item.1 item.2)
      Nat.lt_wfRel.wf

/-! This is deliberately a proposition.  `checked = true` can establish the
finite CFG shape, but only these witnesses establish semantic induction and
termination of completed loop iterations. -/
structure InductiveKernelLoopCertificate (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (function : KernelFunction) (shape : KernelLoopShapeCertificate)
    (contract : KernelLoopContract) : Prop where
  shapeChecked : shape.checked function = true
  establishAtFunctionEntry : function.span.start = shape.headerRva ->
    ∀ state, contract.headerPrecondition state ->
      contract.invariant shape.headerRva state
  establishAtIncomingEdges : ∀ edge, edge ∈ shape.entryEdges function ->
    ∀ before after,
      contract.entryPrecondition edge before ->
      ExactKernelEdgeTransition pe imports environment edge before after ->
      contract.invariant shape.headerRva after
  preserveInternalEdges : ∀ edge, edge ∈ shape.internalEdges function ->
    ∀ before after,
      contract.invariant edge.source before ->
      ExactKernelEdgeTransition pe imports environment edge before after ->
      contract.invariant edge.target after
  rankNonincreasingOffBackEdge : ∀ edge,
    edge ∈ shape.internalEdges function -> edge ≠ shape.backEdge ->
    ∀ before after,
      contract.invariant edge.source before ->
      ExactKernelEdgeTransition pe imports environment edge before after ->
      contract.rank edge.target after ≤ contract.rank edge.source before
  rankDecreasesOnBackEdge : ∀ before after,
    contract.invariant shape.latchRva before ->
    ExactKernelEdgeTransition pe imports environment shape.backEdge before after ->
    contract.rank shape.headerRva after < contract.rank shape.latchRva before
  preserveExitPostconditions : ∀ edge, edge ∈ shape.exitEdges function ->
    ∀ before after,
      contract.invariant edge.source before ->
      ExactKernelEdgeTransition pe imports environment edge before after ->
      contract.exitPostcondition edge before after

def KernelLoopInventory.SemanticallyInductive (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (inventory : KernelLoopInventory)
    (contracts : Nat -> Nat -> KernelLoopContract) : Prop :=
  ∀ functionCertificate, functionCertificate ∈ inventory.functions ->
    ∀ function,
      listAt? program.functions functionCertificate.functionIndex = some function ->
      ∀ loopIndex shape, listAt? functionCertificate.loops loopIndex = some shape ->
        InductiveKernelLoopCertificate pe imports environment function shape
          (contracts functionCertificate.functionIndex loopIndex)

theorem InductiveKernelLoopCertificate.backEdge_descends
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract}
    (certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract) {before after : NativeExecution}
    (invariant : contract.invariant shape.latchRva before)
    (transition : ExactKernelEdgeTransition pe imports environment
      shape.backEdge before after) :
    contract.RankRelation (shape.headerRva, after) (shape.latchRva, before) :=
  certificate.rankDecreasesOnBackEdge before after invariant transition

theorem InductiveKernelLoopCertificate.preserveExactInternal
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract} {before after : NativeExecution}
    (certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract)
    (step : ExactKernelEdgeStep program pe imports environment targets before after)
    (member : step.edge ∈ shape.internalEdges function)
    (invariant : contract.invariant step.edge.source before) :
    contract.invariant step.edge.target after :=
  certificate.preserveInternalEdges step.edge member before after invariant
    step.edgeTransition

theorem InductiveKernelLoopCertificate.preserveExactExit
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract} {before after : NativeExecution}
    (certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract)
    (step : ExactKernelEdgeStep program pe imports environment targets before after)
    (member : step.edge ∈ shape.exitEdges function)
    (invariant : contract.invariant step.edge.source before) :
    contract.exitPostcondition step.edge before after :=
  certificate.preserveExitPostconditions step.edge member before after invariant
    step.edgeTransition

theorem InductiveKernelLoopCertificate.exactBackEdgeDescends
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract} {before after : NativeExecution}
    (certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract)
    (step : ExactKernelEdgeStep program pe imports environment targets before after)
    (isBackEdge : step.edge = shape.backEdge)
    (invariant : contract.invariant shape.latchRva before) :
    contract.RankRelation (shape.headerRva, after) (shape.latchRva, before) := by
  have transition : ExactKernelEdgeTransition pe imports environment
      shape.backEdge before after := by
    simpa [isBackEdge] using step.edgeTransition
  exact certificate.backEdge_descends invariant transition

/-! A traversal is an explicitly finite proof object.  Internal edges use the
inductive invariant, and every completed iteration uses the checked back edge
and its descending rank.  Absence of either the loop certificate or a final
exit constructor leaves no way to build the traversal. -/
inductive ExactKernelLoopTraversal
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (targets : KernelIndirectTargetInventory)
    (function : KernelFunction) (shape : KernelLoopShapeCertificate)
    (contract : KernelLoopContract)
    (certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract) :
    NativeExecution -> NativeExecution -> Prop
  | exit (before after)
      (step : ExactKernelEdgeStep program pe imports environment targets before after)
      (sameFunction : step.run.function = function)
      (member : step.edge ∈ shape.exitEdges function)
      (invariant : contract.invariant step.edge.source before) :
      ExactKernelLoopTraversal program pe imports environment targets function shape
        contract certificate before after
  | advance (before middle after)
      (step : ExactKernelEdgeStep program pe imports environment targets before middle)
      (sameFunction : step.run.function = function)
      (member : step.edge ∈ shape.internalEdges function)
      (notBackEdge : step.edge ≠ shape.backEdge)
      (invariant : contract.invariant step.edge.source before)
      (rest : ExactKernelLoopTraversal program pe imports environment targets
        function shape contract certificate middle after) :
      ExactKernelLoopTraversal program pe imports environment targets function shape
        contract certificate before after
  | iterate (before middle after)
      (step : ExactKernelEdgeStep program pe imports environment targets before middle)
      (sameFunction : step.run.function = function)
      (isBackEdge : step.edge = shape.backEdge)
      (invariant : contract.invariant shape.latchRva before)
      (rest : ExactKernelLoopTraversal program pe imports environment targets
        function shape contract certificate middle after) :
      ExactKernelLoopTraversal program pe imports environment targets function shape
        contract certificate before after

theorem ExactKernelLoopTraversal.nativeSteps
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract}
    {certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract} {before after : NativeExecution}
    (traversal : ExactKernelLoopTraversal program pe imports environment targets
      function shape contract certificate before after) :
    NativeSteps pe imports environment before after := by
  induction traversal with
  | exit before after step => exact step.nativeSteps
  | advance before middle after step _ _ _ _ _ induction =>
      exact step.nativeSteps.trans induction
  | iterate before middle after step _ _ _ _ induction =>
      exact step.nativeSteps.trans induction

theorem ExactKernelLoopTraversal.exitPostcondition
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {function : KernelFunction} {shape : KernelLoopShapeCertificate}
    {contract : KernelLoopContract}
    {certificate : InductiveKernelLoopCertificate pe imports environment
      function shape contract} {before after : NativeExecution}
    (traversal : ExactKernelLoopTraversal program pe imports environment targets
      function shape contract certificate before after) :
    ∃ edge exitBefore,
      edge ∈ shape.exitEdges function ∧
      contract.invariant edge.source exitBefore ∧
      ExactKernelEdgeTransition pe imports environment edge exitBefore after ∧
      contract.exitPostcondition edge exitBefore after := by
  induction traversal with
  | exit before after step sameFunction member invariant =>
      exact ⟨step.edge, before, member, invariant, step.edgeTransition,
        certificate.preserveExactExit step member invariant⟩
  | advance before middle after step sameFunction member notBack invariant rest induction =>
      exact induction
  | iterate before middle after step sameFunction isBack invariant rest induction =>
      exact induction

def ExactKernelDispatches (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (targets : KernelIndirectTargetInventory) (entryRva : Nat)
    (before after : MachineState) (events : List NativeExternalEvent) : Prop :=
  ExactKernelCFGExecution program pe imports environment targets
    (.running entryRva 0 before [] 0 []) (.returned after events)

theorem ExactKernelDispatches.nativeDispatches
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {entryRva : Nat} {before after : MachineState}
    {events : List NativeExternalEvent}
    (execution : ExactKernelDispatches program pe imports environment targets
      entryRva before after events) :
    NativeDispatches pe imports environment entryRva before after events :=
  execution.nativeSteps

/-! This certificate is strictly stronger than `KernelOperationRefines`: it
requires the operation execution to be assembled from exact block runs over a
checked CFG, with complete finite indirect-target and loop inventories. -/
structure KernelOperationCFGCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (abi : KernelABIRelation)
    (targets : KernelIndirectTargetInventory) (loops : KernelLoopInventory)
    (contracts : Nat -> Nat -> KernelLoopContract)
    (operation : KernelOperation) : Prop where
  exactCfg : program.checked pe imports = true
  exactIndirectTargets : targets.checked program pe imports = true
  exactLoopInventory : loops.checked program = true
  loopsInductive : loops.SemanticallyInductive program pe imports environment contracts
  everyBlockSound : ∀ function ∈ program.functions, ∀ block ∈ function.blocks,
    block.SymbolicExecutionSound pe imports
  simulate : ∀ request before,
    request.operation = operation -> abi.requestRelated request before ->
    ∀ response, AbstractKernelTransition request response ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? operation.role = some entryRva ∧
        ExactKernelDispatches program pe imports environment targets
          entryRva before after nativeEvents ∧
        abi.responseRelated request response after nativeEvents ∧
        MemoryAgreesOutside (abi.scratchFootprint request)
          after.memory before.memory

theorem KernelOperationCFGCertificate.refines
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {abi : KernelABIRelation}
    {targets : KernelIndirectTargetInventory} {loops : KernelLoopInventory}
    {contracts : Nat -> Nat -> KernelLoopContract} {operation : KernelOperation}
    (certificate : KernelOperationCFGCertificate program pe imports environment abi
      targets loops contracts operation) :
    KernelOperationRefines program pe imports environment abi operation := by
  intro request before operationMatches related response abstractTransition
  obtain ⟨entryRva, after, nativeEvents, entry, execution, result, frame⟩ :=
    certificate.simulate request before operationMatches related response
      abstractTransition
  exact ⟨entryRva, after, nativeEvents, entry, execution.nativeDispatches,
    result, frame⟩

structure CompiledKernelCFGCertificate
    (binding : KernelArtifactBinding) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (abi : KernelABIRelation) (targets : KernelIndirectTargetInventory)
    (loops : KernelLoopInventory)
    (contracts : Nat -> Nat -> KernelLoopContract) : Prop where
  artifacts : binding.Valid pe
  operations : ∀ operation,
    KernelOperationCFGCertificate program pe imports environment abi targets loops
      contracts operation

theorem CompiledKernelCFGCertificate.refines
    {binding : KernelArtifactBinding} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {abi : KernelABIRelation} {targets : KernelIndirectTargetInventory}
    {loops : KernelLoopInventory}
    {contracts : Nat -> Nat -> KernelLoopContract}
    (certificate : CompiledKernelCFGCertificate binding program pe imports
      environment abi targets loops contracts) :
    CompiledKernelRefinement binding program pe imports environment abi := by
  let structural := certificate.operations .programLookup
  exact {
    artifacts := certificate.artifacts
    exactCfg := structural.exactCfg
    blocksSound := structural.everyBlockSound
    operations := fun operation => (certificate.operations operation).refines
  }

#print axioms KernelLoopContract.rankRelation_wellFounded
#print axioms InductiveKernelLoopCertificate.backEdge_descends
#print axioms ExactKernelCFGExecution.nativeSteps
#print axioms ExactKernelLoopTraversal.exitPostcondition
#print axioms KernelOperationCFGCertificate.refines
#print axioms CompiledKernelCFGCertificate.refines

end StageA.Relational.InterpreterKernelLoop
