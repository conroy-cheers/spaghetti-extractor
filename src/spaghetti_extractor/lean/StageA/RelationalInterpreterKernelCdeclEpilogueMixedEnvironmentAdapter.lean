import StageA.RelationalInterpreterKernelCdeclEpilogueExternalPayload
import StageA.RelationalInterpreterMixedEnvironment

namespace StageA.Relational.InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld

/-!
# Mixed-environment cdecl response adapter

The whole-program mixed environment relates one concrete original protocol
action to one concrete native action.  The cdecl payload layer additionally
requires a checked static machine-call contract and an exact semantic
`CallEvent`.  Those facts are not fields of `MixedRelationContract`.

`MixedCDeclExternalReturnResidual` records only that missing bridge.  Given it,
an actual decoded native dispatch and the whole-program environment proof
construct the candidate return action, the checked cdecl response, and its
singleton response trace.  No submitted endpoint or report status is used.
-/

/-- Facts intentionally absent from the whole-program mixed relation:

* the checked static machine-call contract used by the cdecl proof;
* conversion of this mixed boundary to the older same-world boundary;
* agreement of the protocol/native actions with the two result environments;
* the exact semantic call identity and argument list.

The two result-agreement fields are local to the actual event.  The global
machine-call law remains the existing `CheckedExactLockstepExternalReturn`.
-/
structure MixedCDeclExternalReturnResidual
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (suspension : WorldExternalSuspension)
    (dispatch : ExactNativeExternalDispatch candidate)
    (semantic : CallEvent)
    (originalResult : WorldExternalResult) where
  context : StaticProofContext
  machineContract : MachineImportCallContract
  originalEnvironment : WorldExternalEnvironment
  candidateEnvironment : WorldExternalEnvironment
  checkedMachineCall :
    CheckedExactLockstepExternalReturn context suspension.site machineContract
      originalEnvironment candidateEnvironment
  originalReturned :
    original.protocolEnvironment.action suspension.request =
      .returned originalResult
  siteIdExact : suspension.site.id = suspension.siteId
  importExact : machineContract.imported = suspension.imported
  worldExact : suspension.world = dispatch.world
  boundaryState :
    ExternalBoundaryStateRel context suspension.world
      suspension.site.boundaryInvariant suspension.state dispatch.decodedState
  boundaryArguments :
    externalCallArgumentsRelated context suspension.world suspension.arguments
      dispatch.arguments = true
  originalResultExact :
    originalEnvironment.result dispatch.eventIndex suspension.event =
      originalResult
  candidateResultExact :
    forall candidateResult,
      dispatch.action = .returned candidateResult ->
        candidateEnvironment.result dispatch.eventIndex
          (nativeWorldExternalEvent dispatch.event suspension.site dispatch.world) =
            candidateResult
  semanticKind : semantic.kind = .external
  semanticImport : ImportMatchesCallEvent dispatch.imported semantic
  semanticArguments : dispatch.arguments = semantic.arguments

/-- The concrete mixed boundary plus the dependent residual determines the
static cdecl boundary. -/
theorem MixedCDeclExternalReturnResidual.externalBoundary
    (contract : MixedRelationContract)
    (residual : MixedCDeclExternalReturnResidual original candidate suspension
      dispatch semantic originalResult)
    (mixedBoundary :
      contract.externalBoundariesRelated suspension dispatch.boundary) :
    ExternalCallBoundaryRelated residual.context suspension.site
      residual.machineContract suspension.event
      (nativeWorldExternalEvent dispatch.event suspension.site dispatch.world) := by
  rcases mixedBoundary with
    ⟨eventSite, eventImport, eventArguments, eventState, eventWorld, _eventIndex,
      dispatchImport, _worldsRelated, _statesRelated, _argumentsRelated⟩
  refine ⟨?_, rfl, ?_, ?_, ?_, ?_, ?_⟩
  · exact eventSite.trans residual.siteIdExact.symm
  · exact eventWorld.trans residual.worldExact
  · exact eventImport.trans residual.importExact.symm
  · exact dispatchImport.symm.trans residual.importExact.symm
  · simp only [nativeWorldExternalEvent]
    rw [eventWorld, eventState]
    exact residual.boundaryState
  · simp only [nativeWorldExternalEvent]
    rw [eventWorld, eventArguments]
    exact residual.boundaryArguments

/-- Everything obtained from the actual mixed return is retained alongside the
existing cdecl response.  In particular, the original result used by the
protocol and the result used by the lockstep environment are definitionally
tied by `originalResultExact`. -/
structure CheckedMixedCDeclKernelExternalResponse
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (suspension : WorldExternalSuspension)
    (dispatch : ExactNativeExternalDispatch candidate)
    (semantic : CallEvent)
    (originalResult : WorldExternalResult) where
  candidateResult : WorldExternalResult
  nativeReturned : dispatch.action = .returned candidateResult
  worldsRelated :
    contract.worldsRelated originalResult.world candidateResult.world
  statesRelated :
    contract.runtimeStatesRelated originalResult.world candidateResult.world
      originalResult.state candidateResult.state
  response : CheckedOneToOneKernelExternalResponse semantic dispatch.event
  originalResultExact :
    response.originalEnvironment.result dispatch.eventIndex suspension.event =
      originalResult

/-- An actual dispatch and the whole-program exact 1:1 environment proof force
the native action to return.  Static machine-call and semantic identity facts
come only from the explicit dependent residual. -/
def checkedMixedCDeclKernelExternalResponse
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate)
    (semantic : CallEvent)
    (originalResult : WorldExternalResult)
    (mixedBoundary :
      contract.externalBoundariesRelated suspension dispatch.boundary)
    (frameBoundary :
      MixedExternalFrameBoundaryRelated frames suspension callbacks
        dispatch.continuationRva dispatch.calls)
    (environmentsRefine :
      ExactOneToOneMixedExternalEnvironmentsRefine original candidate contract
        frames)
    (residual : MixedCDeclExternalReturnResidual original candidate suspension
      dispatch semantic originalResult) :
    CheckedMixedCDeclKernelExternalResponse original candidate contract
      suspension dispatch semantic originalResult := by
  have related := environmentsRefine suspension callbacks dispatch mixedBoundary
    frameBoundary
  rw [residual.originalReturned] at related
  cases actionExact : dispatch.action with
  | returned candidateResult =>
      rw [actionExact] at related
      have resultRelated :
          contract.worldsRelated originalResult.world candidateResult.world /\
            contract.runtimeStatesRelated originalResult.world
              candidateResult.world originalResult.state candidateResult.state := by
        simpa [MixedExternalEnvironmentActionsRelated] using related
      let candidateEvent :=
        nativeWorldExternalEvent dispatch.event suspension.site dispatch.world
      have boundary : ExternalCallBoundaryRelated residual.context suspension.site
          residual.machineContract suspension.event candidateEvent := by
        exact residual.externalBoundary contract mixedBoundary
      have nativeReturned :
          candidate.environment.action dispatch.eventIndex dispatch.event
              dispatch.world = .returned candidateResult := by
        simpa [ExactNativeExternalDispatch.action] using actionExact
      let response :
          CheckedOneToOneKernelExternalResponse semantic dispatch.event := {
        context := residual.context
        site := suspension.site
        contract := residual.machineContract
        originalEnvironment := residual.originalEnvironment
        candidateEnvironment := residual.candidateEnvironment
        nativeEnvironment := candidate.environment
        world := dispatch.world
        eventIndex := dispatch.eventIndex
        originalEvent := suspension.event
        candidateEvent := candidateEvent
        candidateEventExact := rfl
        candidateResult := candidateResult
        checked := residual.checkedMachineCall
        boundary := boundary
        candidateResultExact := residual.candidateResultExact candidateResult
          actionExact
        nativeReturned := nativeReturned
        semanticKind := residual.semanticKind
        importMatches := residual.semanticImport
        argumentsExact := residual.semanticArguments
      }
      have responseOriginalEnvironment :
          response.originalEnvironment = residual.originalEnvironment := rfl
      exact {
        candidateResult := candidateResult
        nativeReturned := actionExact
        worldsRelated := resultRelated.1
        statesRelated := resultRelated.2
        response := response
        originalResultExact := by
          rw [responseOriginalEnvironment]
          exact residual.originalResultExact
      }
  | callback entry =>
      rw [actionExact] at related
      simp [MixedExternalEnvironmentActionsRelated] at related
  | terminated world =>
      rw [actionExact] at related
      simp [MixedExternalEnvironmentActionsRelated] at related
  | blocked reason =>
      rw [actionExact] at related
      simp [MixedExternalEnvironmentActionsRelated] at related

/-- The checked response is one exact element of the cdecl response trace. -/
def CheckedMixedCDeclKernelExternalResponse.oneToOneTrace
    (checked : CheckedMixedCDeclKernelExternalResponse original candidate contract
      suspension dispatch semantic originalResult) :
    CheckedOneToOneExternalResponseTrace [semantic] [dispatch.event] :=
  .cons checked.response .nil

/-- Close an `invokeCall` external response trace for the actual dispatch. -/
def CheckedMixedCDeclKernelExternalResponse.invokeExternalTrace
    (checked : CheckedMixedCDeclKernelExternalResponse original candidate contract
      suspension dispatch semantic originalResult)
    (responseExact : result = environment.invokeCall semantic logical) :
    CheckedResponseExternalTrace
      (.invokeCall records environment resolveCodeTarget semantic logical)
      (.call result) [dispatch.event] :=
  .invokeExternal responseExact checked.oneToOneTrace

/-- Close a single-external-call interpreter-step response trace once the
operation theorem fixes that call's position in the abstract event list. -/
def CheckedMixedCDeclKernelExternalResponse.interpreterStepSomeTrace
    (checked : CheckedMixedCDeclKernelExternalResponse original candidate contract
      suspension dispatch semantic originalResult)
    (eventsExact : externalCallEvents result.events = [semantic]) :
    CheckedResponseExternalTrace
      (.interpreterStep records environment sourceOffset logical)
      (.interpreterStep (some result)) [dispatch.event] := by
  apply CheckedResponseExternalTrace.interpreterStepSome
  rw [eventsExact]
  exact checked.oneToOneTrace

#print axioms MixedCDeclExternalReturnResidual.externalBoundary
#print axioms checkedMixedCDeclKernelExternalResponse
#print axioms CheckedMixedCDeclKernelExternalResponse.oneToOneTrace
#print axioms CheckedMixedCDeclKernelExternalResponse.invokeExternalTrace
#print axioms CheckedMixedCDeclKernelExternalResponse.interpreterStepSomeTrace

end StageA.Relational.InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter
