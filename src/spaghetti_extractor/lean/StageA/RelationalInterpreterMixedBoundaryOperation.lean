import StageA.RelationalInterpreterMixedConstructiveSourceClassifier

namespace StageA.Relational.InterpreterMixedBoundaryOperation

open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact native boundary-to-operation bridges

A native launch wrapper can stop before the first checked kernel-operation
entry.  Closing that boundary requires a real silent candidate path to an
operation state and a checked operation certificate from that state.  This
module composes those two proof objects without accepting submitted
observations, successor endpoints, or endpoint relations.
-/

/-- A checked silent native prefix from a classified boundary to the input of
one exact mixed kernel-operation certificate. -/
structure ExactMixedKernelBoundaryToOperationBridge
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (sourceRva : Nat)
    (owner : ExactCandidateKernelEntry program)
    (originalBefore : WorldExecution)
    (boundaryBefore : NativeWorldExecution) where
  operationBefore : NativeWorldExecution
  candidatePrefix : NonemptyRelatedPath candidate.transitionSystem
    boundaryBefore [] operationBefore
  certificate : MixedKernelOperationComponentCertificate original candidate
    contract invariant program abi dispatches candidateAuthority sourceRva
    owner.operation owner.entryRva originalBefore operationBefore

/-- Prepend the exact silent boundary prefix to the candidate side of the
checked operation chunk.  Both resulting paths remain nonempty, and all
operation observations and the operation-derived related endpoint are
preserved exactly. -/
def ExactMixedKernelBoundaryToOperationBridge.toChunk
    (bridge : ExactMixedKernelBoundaryToOperationBridge original candidate
      contract invariant program abi dispatches candidateAuthority sourceRva
      owner originalBefore boundaryBefore) :
    MixedKernelChunkPaths original candidate contract invariant originalBefore
      boundaryBefore := {
  originalObservations := bridge.certificate.paths.originalObservations
  candidateObservations := bridge.certificate.paths.candidateObservations
  originalAfter := bridge.certificate.paths.originalAfter
  candidateAfter := bridge.certificate.paths.candidateAfter
  originalPath := bridge.certificate.paths.originalPath
  candidatePath := by
    simpa using
      bridge.candidatePrefix.trans bridge.certificate.paths.candidatePath
  observationsChecked := bridge.certificate.paths.observationsChecked
  afterRelated := bridge.certificate.paths.afterRelated
}

#print axioms ExactMixedKernelBoundaryToOperationBridge.toChunk

end StageA.Relational.InterpreterMixedBoundaryOperation
