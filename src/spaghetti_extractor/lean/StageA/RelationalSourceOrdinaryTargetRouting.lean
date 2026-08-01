import StageA.RelationalInterpreterSemanticRefinement
import StageA.RelationalSourceInterpreterKernel

namespace StageA.Relational.SourceWorld.OrdinaryTargetRouting

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.InterpreterTransfer
open StageA.Relational.SourceWorld.InterpreterKernel

/-!
# Ordinary source-target routing

This module is the stable adapter between checked ordinary `ProgramRecord`
semantics and the target-local routing interface.  Generated modules provide
only facts from existing proof artifacts:

* the exact record/path normalization certificate;
* exact target and decoded-region lookup;
* exact machine-call-contract selection and symbolic evaluation;
* total ordinary evaluator execution; and
* the control/fault projection not carried by the fused machine theorem.

The adapter derives evaluator selection, the concrete source step, and the
complete `MachineState` equality. Generated proofs do not restate a universal
machine equality for every target. Missing, duplicate, x87-classified, or
failed evaluator lookups cannot construct the certificate.
-/

/-- Exact static association of one ordinary source record with the decoded
world target that carries the same PE span.  `regionExact` is deliberately a
lookup equality, rather than list membership or a submitted region ID. -/
structure ExactOrdinaryTargetBinding
    (pe : PE32) (program : Program) (targetId sourceRva : Nat)
    (record : ProgramRecord) (path : ExactNormalizedTransferPath)
    (transfer : SemanticTransfer) (region : RegionRelation) : Prop where
  originalRole : program.worldProgram.candidate = false
  originalPeExact : program.worldProgram.context.originalPe = pe
  sourceExact : sourceRvaForTarget? program targetId = some sourceRva
  classificationExact : x87Classified program sourceRva = some false
  recordLookupExact : lookupRecord? program.records sourceRva = some record
  regionExact : regionById program.worldProgram.regions targetId = some region
  pathRecordExact : path.record = record
  pathSourceExact : path.sourceRva = sourceRva
  regionStartExact : region.original.start = path.sourceRva
  regionStopExact : region.original.stop = path.stopRva
  nonX87 :
    StageA.Relational.X87.spanStartsWithX87Command pe region.original = false
  normalization :
    ExactProgramRecordNormalizationCertificate pe path transfer

/-- The compatibility selector reduces to call-stack-sensitive ordinary
evaluation with an empty return stack. -/
theorem ExactOrdinaryTargetBinding.targetStep_eq_ordinaryStepWithCalls
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (state : MachineState) :
    targetStep? program targetId state =
      ordinaryStepWithCalls? program targetId record state [] := by
  simp [targetStep?, binding.sourceExact, binding.classificationExact,
    targetStepWithCalls?, binding.recordLookupExact]

/-- The whole-program target selector carries the active return stack into the
ordinary evaluator's machine-import normalization. -/
theorem ExactOrdinaryTargetBinding.targetStepWithCalls_eq_ordinaryStepWithCalls
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (state : MachineState) (calls : List Nat) :
    targetStepWithCalls? program targetId state calls =
      ordinaryStepWithCalls? program targetId record state calls := by
  simp [targetStepWithCalls?, binding.sourceExact,
    binding.classificationExact, binding.recordLookupExact]

/-- The raw source record executes the exact normalized PE path.  This is the
cached generated semantic-refinement theorem, reached through the checked
record decoder rather than an independently supplied source function. -/
theorem ExactOrdinaryTargetBinding.recordMacroStepExact
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (state : MachineState) :
    record.interpret (localEnvironment state) (machineFromFormal state) =
      runExactNormalizedPath pe path (localEnvironment state) state := by
  rw [<- binding.pathRecordExact]
  exact binding.normalization.rawMacroStep (localEnvironment state) state

/-- Reuse a generated fused semantic theorem without re-running symbolic
execution.  This theorem intentionally concludes equality of the interpreter
machine projection.  The source interpreter does not carry x87, undefined,
or FS state in `InterpreterMachine`, so complete `MachineState` equality is a
separate checked projection below. -/
theorem ExactOrdinaryTargetBinding.fusedInterpreterMachineExact
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (fused : ExactSemanticTransferFusedMachineRefinement pe imports
      region.original transfer)
    (state : MachineState) (symbolic : SymbolicBehavior)
    (behavior : RelationalBehavior) (result : MacroResult)
    (symbolicExact :
      executePE32SymbolicSpan pe imports region.original = some symbolic)
    (evaluatedExact :
      evalBehavior false region.targets state symbolic = some behavior)
    (recordExact :
      record.interpret (localEnvironment state) (machineFromFormal state) =
        some result) :
    machineFromFormal (behavior.nextMachineState state) = result.state := by
  have decoded : record.decode = some transfer := by
    rw [<- binding.pathRecordExact]
    exact binding.normalization.recordDecoded
  have transferChecked : transfer.checked = true :=
    binding.normalization.transferChecked
  have transferExact :
      transfer.execute (localEnvironment state) (machineFromFormal state) =
        some result := by
    rw [<- record.macroStep_semantic_correspondence transfer decoded
      transferChecked]
    exact recordExact
  exact fused region.targets state (localEnvironment state) symbolic behavior
    result symbolicExact evaluatedExact transferExact

/-- Equality of the interpreter projection extends to the full ordinary
machine state once the legacy x87 representation is known to be stable.  The
other omitted fields are preserved definitionally by `nextMachineState` and
`formalFromInterpreter`. -/
theorem formalFromInterpreter_fusedMachineExact
    (input : MachineState) (behavior : RelationalBehavior)
    (result : InterpreterMachine)
    (noX87Effect : behavior.x87Effect = none)
    (legacyX87Exact : (behavior.nextMachineState input).x87 = input.x87)
    (machineExact : machineFromFormal (behavior.nextMachineState input) = result) :
    InterpreterMachineBridge.formalFromInterpreter input result =
      behavior.nextMachineState input := by
  subst result
  cases input with
  | mk inputRegisters inputMemory inputUndefined inputX87 inputPhysical
      inputSemantics inputEflags inputFsBase =>
    cases behavior with
    | mk registers x87 x87Effect x87Fault writes eflags outcome =>
      cases registers
      simp_all [InterpreterMachineBridge.formalFromInterpreter,
        machineFromFormal, RelationalBehavior.nextMachineState,
        Registers.get, InterpreterMachineBridge.formalRegister]

/-- Exact decoded evaluator data after target lookup and call-contract
selection.  The symbolic behavior may depend on the active return stack because
`machineImportContractsAt` deliberately uses the continuation to disambiguate
multiple call-site contracts. -/
structure ExactDecodedOrdinaryTargetEvaluator
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region) where
  symbolic : List Nat -> SymbolicBehavior
  normalized : List Nat -> NormalizedSymbolicBehavior
  symbolicExact : forall calls,
    regionBehaviorWithMachineCallContracts pe
        program.worldProgram.context.originalImports
        (program.worldProgram.machineImportContractsAt targetId calls)
        region.original = some (symbolic calls)
  normalizedExact : forall calls,
    normalizeSymbolicBehavior false region.targets (symbolic calls) =
      some (normalized calls)

def ExactDecodedOrdinaryTargetEvaluator.behavior
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    (evaluator : ExactDecodedOrdinaryTargetEvaluator binding)
    (state : MachineState) (calls : List Nat) : RelationalBehavior :=
  (evaluator.normalized calls).eval state

/-- Region lookup, side selection, PE identity, x87 exclusion, call-contract
selection, and symbolic evaluation together identify the actual decoded-world
evaluator. -/
theorem ExactDecodedOrdinaryTargetEvaluator.decodedBehaviorExact
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    (evaluator : ExactDecodedOrdinaryTargetEvaluator binding)
    (state : MachineState) (calls : List Nat) :
    decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state calls =
      some (evaluator.behavior state calls) := by
  simp [decodedWorldRegionBehaviorWithCalls, binding.regionExact,
    binding.originalRole, binding.originalPeExact, binding.nonX87,
    evaluator.symbolicExact calls,
    ExactDecodedOrdinaryTargetEvaluator.behavior,
    evalBehavior_of_normalized false region.targets state
      (evaluator.symbolic calls) (evaluator.normalized calls)
      (evaluator.normalizedExact calls)]

/-- Control/fault identity is independent of the full machine state. -/
inductive EvaluatedEffectKind where
  | outcome (outcome : PureOutcome)
  | fault (cause : ModeledFault)
deriving DecidableEq

def evaluatedEffectKind : EvaluatedEffect -> EvaluatedEffectKind
  | .outcome _ outcome => .outcome outcome
  | .fault cause => .fault cause

def evaluatedEffectMachine? : EvaluatedEffect -> Option MachineState
  | .outcome state _ => some state
  | .fault _ => none

/-- Effect equality is completely determined by the control/fault projection
and the optional machine-state projection. -/
theorem EvaluatedEffect.eq_of_kind_and_machine
    {left right : EvaluatedEffect}
    (kindExact : evaluatedEffectKind left = evaluatedEffectKind right)
    (machineExact : evaluatedEffectMachine? left =
      evaluatedEffectMachine? right) : left = right := by
  cases left <;> cases right <;>
    simp_all [evaluatedEffectKind, evaluatedEffectMachine?]

/-- The remaining dynamic evidence for an ordinary target.  The expensive
facts are projection-sized and can be cached independently: `kindExact` comes
from normalized control plus call-contract arguments, while `machineExact`
comes from fused machine refinement plus checked preservation of the formal
state fields not represented by `InterpreterMachine`. -/
structure CheckedOrdinaryTargetEffect
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (decoded : ExactDecodedOrdinaryTargetEvaluator binding) where
  rawSourceStep : MachineState -> EvaluatedStep
  sourceStep : MachineState -> List Nat -> EvaluatedStep
  ordinaryStepExact : forall state,
    ordinaryStep? program record state = some (rawSourceStep state)
  contractStepExact : forall state calls,
    applyOrdinaryMachineImportContractsToStep?
        (program.worldProgram.machineImportContractsAt targetId calls)
        (rawSourceStep state) =
      some (sourceStep state calls)
  kindExact : forall state calls,
    evaluatedEffectKind (sourceStep state calls).effect =
      evaluatedEffectKind
        (evaluatedEffectOfBehavior state (decoded.behavior state calls))
  machineExact : forall state calls,
    evaluatedEffectMachine? (sourceStep state calls).effect =
      evaluatedEffectMachine? (evaluatedEffectOfBehavior state
        (decoded.behavior state calls))

/-- Exact source/decoder semantic replay before world routing.  Unlike a
`TargetLocalEffectExact`, this object retains the two independently computed
evaluations and their equations: the raw `ordinaryStep?`, call-contract
normalization, decoded symbolic normalization, and final effect equality. -/
structure ExactOrdinaryTargetSemanticReplay
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region) where
  decoded : ExactDecodedOrdinaryTargetEvaluator binding
  rawSourceStep : MachineState -> EvaluatedStep
  sourceStep : MachineState -> List Nat -> EvaluatedStep
  ordinaryStepExact : forall state,
    ordinaryStep? program record state = some (rawSourceStep state)
  contractStepExact : forall state calls,
    applyOrdinaryMachineImportContractsToStep?
        (program.worldProgram.machineImportContractsAt targetId calls)
        (rawSourceStep state) =
      some (sourceStep state calls)
  effectExact : forall state calls,
    (sourceStep state calls).effect =
      evaluatedEffectOfBehavior state (decoded.behavior state calls)

/-- Assemble a total replay from checked evaluator success and one exact
effect equation.  Generated target shards use this constructor so all
`Option.get` projections are tied to the actual source and decoded evaluators;
no independently submitted step or behavior can enter the certificate. -/
noncomputable def ExactOrdinaryTargetSemanticReplay.ofCheckedEvaluators
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    (binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region)
    (rawTotal : forall state, (ordinaryStep? program record state).isSome)
    (contractTotal : forall state calls,
      (applyOrdinaryMachineImportContractsToStep?
        (program.worldProgram.machineImportContractsAt targetId calls)
        ((ordinaryStep? program record state).get (rawTotal state))).isSome)
    (symbolicTotal : forall calls,
      (regionBehaviorWithMachineCallContracts pe
        program.worldProgram.context.originalImports
        (program.worldProgram.machineImportContractsAt targetId calls)
        region.original).isSome)
    (normalizedTotal : forall calls,
      (normalizeSymbolicBehavior false region.targets
        ((regionBehaviorWithMachineCallContracts pe
          program.worldProgram.context.originalImports
          (program.worldProgram.machineImportContractsAt targetId calls)
          region.original).get (symbolicTotal calls))).isSome)
    (effectExact : forall state calls,
      let raw := (ordinaryStep? program record state).get (rawTotal state)
      let source :=
        (applyOrdinaryMachineImportContractsToStep?
          (program.worldProgram.machineImportContractsAt targetId calls) raw).get
            (contractTotal state calls)
      let symbolic :=
        (regionBehaviorWithMachineCallContracts pe
          program.worldProgram.context.originalImports
          (program.worldProgram.machineImportContractsAt targetId calls)
          region.original).get (symbolicTotal calls)
      let normalized :=
        (normalizeSymbolicBehavior false region.targets symbolic).get
          (normalizedTotal calls)
      source.effect = evaluatedEffectOfBehavior state (normalized.eval state)) :
    ExactOrdinaryTargetSemanticReplay binding := by
  let rawSourceStep : MachineState -> EvaluatedStep := fun state =>
    (ordinaryStep? program record state).get (rawTotal state)
  let sourceStep : MachineState -> List Nat -> EvaluatedStep := fun state calls =>
    (applyOrdinaryMachineImportContractsToStep?
      (program.worldProgram.machineImportContractsAt targetId calls)
      (rawSourceStep state)).get (contractTotal state calls)
  let symbolic : List Nat -> SymbolicBehavior := fun calls =>
    (regionBehaviorWithMachineCallContracts pe
      program.worldProgram.context.originalImports
      (program.worldProgram.machineImportContractsAt targetId calls)
      region.original).get (symbolicTotal calls)
  let normalized : List Nat -> NormalizedSymbolicBehavior := fun calls =>
    (normalizeSymbolicBehavior false region.targets (symbolic calls)).get
      (normalizedTotal calls)
  let decoded : ExactDecodedOrdinaryTargetEvaluator binding := {
    symbolic
    normalized
    symbolicExact := by
      intro calls
      exact (Option.some_get (symbolicTotal calls)).symm
    normalizedExact := by
      intro calls
      exact (Option.some_get (normalizedTotal calls)).symm
  }
  exact {
    decoded
    rawSourceStep
    sourceStep
    ordinaryStepExact := by
      intro state
      exact (Option.some_get (rawTotal state)).symm
    contractStepExact := by
      intro state calls
      exact (Option.some_get (contractTotal state calls)).symm
    effectExact := by
      intro state calls
      simpa [rawSourceStep, sourceStep, symbolic, normalized,
        ExactDecodedOrdinaryTargetEvaluator.behavior, decoded] using
        effectExact state calls
  }

/-- Derive the requested effect certificate from the single total replay.
Control kind and optional machine-state equality are projections of the full
checked effect equality, so they cannot drift from one another. -/
def ExactOrdinaryTargetSemanticReplay.toCheckedOrdinaryTargetEffect
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
  (replay : ExactOrdinaryTargetSemanticReplay binding) :
    CheckedOrdinaryTargetEffect binding replay.decoded where
  rawSourceStep := replay.rawSourceStep
  sourceStep := replay.sourceStep
  ordinaryStepExact := replay.ordinaryStepExact
  contractStepExact := replay.contractStepExact
  kindExact := by
    intro state calls
    exact congrArg evaluatedEffectKind (replay.effectExact state calls)
  machineExact := by
    intro state calls
    exact congrArg evaluatedEffectMachine? (replay.effectExact state calls)

/-- Construct the existing successful-target interface from checked ordinary
facts.  Generated declarations no longer restate `targetStep?` or decoded-world
lookup equalities. -/
def CheckedOrdinaryTargetEffect.toSuccessfulTargetEffectComponents
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded) :
    SuccessfulTargetEffectComponents program targetId where
  sourceStep := checked.sourceStep
  decodedBehavior := decoded.behavior
  sourceStepExact := by
    intro state calls
    rw [binding.targetStepWithCalls_eq_ordinaryStepWithCalls state calls]
    simp only [ordinaryStepWithCalls?, checked.ordinaryStepExact state]
    exact checked.contractStepExact state calls
  decodedBehaviorExact := decoded.decodedBehaviorExact
  effectsExact := by
    intro state calls
    exact EvaluatedEffect.eq_of_kind_and_machine
      (checked.kindExact state calls) (checked.machineExact state calls)

/-- Direct acceptance-facing local-effect adapter. -/
def CheckedOrdinaryTargetEffect.toLocalEffectExact
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded) :
    TargetLocalEffectExact program targetId :=
  checked.toSuccessfulTargetEffectComponents.toLocalEffectExact

end StageA.Relational.SourceWorld.OrdinaryTargetRouting
