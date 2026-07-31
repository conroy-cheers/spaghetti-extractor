import StageA.RelationalInterpreterExactRefinement
import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.InterpreterSemanticRefinement

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterNormalization

/-!
This module is the stable proof boundary used by generated ordinary-transfer
refinement shards.  Generated sources supply exact PE-byte and import-table
facts plus a reduced equality between the typed semantic transfer and the
reviewed exact instruction runner.  No extractor status is represented here.
-/

/-- Cached concrete proof boundary between one exact PE span and its decoded
semantic transfer. Generated shards prove this proposition by reducing the
exact bytes once; downstream composition consumes the opaque theorem without
re-running symbolic execution. -/
def ExactSemanticTransferFusedMachineRefinement
    (pe : PE32) (imports : List PEImport) (span : Span)
    (transfer : SemanticTransfer) : Prop :=
  forall targets state environment symbolic behavior result,
    executePE32SymbolicSpan pe imports span = some symbolic ->
    evalBehavior false targets state symbolic = some behavior ->
    transfer.execute environment (machineFromFormal state) = some result ->
    machineFromFormal (behavior.nextMachineState state) = result.state

end StageA.Relational.InterpreterSemanticRefinement
