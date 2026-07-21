import StageA.X87

namespace StageA.Relational.X87

open StageA.X87

structure AddressRelation where
  code : BitVec 32 -> BitVec 32 -> Prop
  data : BitVec 32 -> BitVec 32 -> Prop

def MetadataRelated (relation : AddressRelation)
    (original candidate : MetadataState) : Prop :=
  original.lastOpcode = candidate.lastOpcode ∧
    relation.code original.instructionPointer candidate.instructionPointer ∧
    original.codeSelector = candidate.codeSelector ∧
    relation.data original.dataPointer candidate.dataPointer ∧
    original.dataSelector = candidate.dataSelector

def StateRelated (relation : AddressRelation)
    (original candidate : PhysicalState) : Prop :=
  original.core = candidate.core ∧
    MetadataRelated relation original.metadata candidate.metadata

def InputRelated (relation : AddressRelation)
    (original candidate : StepInput) : Prop :=
  original.operand = candidate.operand ∧
    original.opcode = candidate.opcode ∧
    relation.code original.instructionPointer candidate.instructionPointer ∧
    original.codeSelector = candidate.codeSelector ∧
    relation.data original.dataPointer candidate.dataPointer ∧
    original.dataSelector = candidate.dataSelector

def ResponseRelated (relation : AddressRelation)
    (original candidate : Response) : Prop :=
  StateRelated relation original.nextState candidate.nextState ∧
    original.store = candidate.store ∧
    original.register = candidate.register ∧
    original.eflagsValue = candidate.eflagsValue ∧
    original.eflagsWriteMask = candidate.eflagsWriteMask ∧
    original.definedness = candidate.definedness ∧
    original.fault = candidate.fault

theorem metadata_after_related (relation : AddressRelation)
    (command : Command) (originalPrevious candidatePrevious : MetadataState)
    (originalInput candidateInput : StepInput)
    (previous : MetadataRelated relation originalPrevious candidatePrevious)
    (input : InputRelated relation originalInput candidateInput) :
    MetadataRelated relation
      (originalPrevious.after command originalInput)
      (candidatePrevious.after command candidateInput) := by
  rcases previous with
    ⟨previousOpcode, previousInstruction, previousCodeSelector,
      previousData, previousDataSelector⟩
  rcases input with
    ⟨_, opcode, instruction, codeSelector, data, dataSelector⟩
  cases memory : command.usesMemoryOperand with
  | false =>
      simpa [MetadataState.after, memory] using
        ⟨opcode, instruction, codeSelector, previousData,
          previousDataSelector⟩
  | true =>
      simpa [MetadataState.after, memory] using
        ⟨opcode, instruction, codeSelector, data, dataSelector⟩

theorem execute_related (semantics : Semantics) (relation : AddressRelation)
    (command : Command) (waitMode : WaitMode)
    (originalState candidateState : PhysicalState)
    (originalInput candidateInput : StepInput)
    (states : StateRelated relation originalState candidateState)
    (inputs : InputRelated relation originalInput candidateInput) :
    ResponseRelated relation
      (semantics.execute command waitMode originalState originalInput)
      (semantics.execute command waitMode candidateState candidateInput) := by
  rcases states with ⟨core, metadata⟩
  have operand := inputs.1
  have step := semantics.step_congr (originalCommand := command)
    (candidateCommand := command) (originalWait := waitMode)
    (candidateWait := waitMode) (originalState := originalState.core)
    (candidateState := candidateState.core)
    (originalInput := originalInput.operand)
    (candidateInput := candidateInput.operand) rfl rfl core operand
  unfold Semantics.execute
  rw [step]
  unfold ResponseRelated StateRelated CoreResponse.toResponse
  constructor
  · constructor
    · rfl
    · exact metadata_after_related relation command
        originalState.metadata candidateState.metadata originalInput candidateInput
        metadata inputs
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem execute_related_and_structurally_valid (semantics : Semantics)
    (complies : semantics.Complies) (relation : AddressRelation)
    (command : Command) (waitMode : WaitMode)
    (originalState candidateState : PhysicalState)
    (originalInput candidateInput : StepInput)
    (states : StateRelated relation originalState candidateState)
    (inputs : InputRelated relation originalInput candidateInput)
    (modeValid : command.waitModeValid waitMode)
    (originalValid : originalInput.validFor command)
    (candidateValid : candidateInput.validFor command) :
    ResponseRelated relation
        (semantics.execute command waitMode originalState originalInput)
        (semantics.execute command waitMode candidateState candidateInput) ∧
      (semantics.execute command waitMode originalState originalInput).structurallyValid
        command waitMode ∧
      (semantics.execute command waitMode candidateState candidateInput).structurallyValid
        command waitMode := by
  exact ⟨execute_related semantics relation command waitMode originalState
      candidateState originalInput candidateInput states inputs,
    semantics.execute_structurallyValid complies command waitMode originalState
      originalInput modeValid originalValid,
    semantics.execute_structurallyValid complies command waitMode candidateState
      candidateInput modeValid candidateValid⟩

end StageA.Relational.X87
