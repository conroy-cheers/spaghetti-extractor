import StageA.RelationalDecode

namespace StageA.Relational.SemanticsChecker

open StageA.Formal

/-- The current symbolic executor consults immutable PE bytes only for the two
x87 memory-load forms. This predicate is deliberately conservative: a dynamic
address still remains on the PE-dependent side until a later certificate proves
that its symbolic address cannot be an immutable image address. -/
def instructionImageContextIndependent : Instruction -> Bool
  | .x87LoadMemory .. | .x87BinaryMemory .. => false
  | _ => true

theorem executeInstructionWithContext_eq_of_imageContextIndependent
    (original candidate : SymbolicImageContext)
    (imports : List PEImport) (pc undefinedSlot : Nat)
    (decoded : DecodedInstruction) (state : SymbolicBehavior)
    (imageBase : original.imageBase = candidate.imageBase)
    (independent :
      instructionImageContextIndependent decoded.instruction = true) :
    executeInstructionWithContext original imports pc undefinedSlot decoded state =
      executeInstructionWithContext candidate imports pc undefinedSlot decoded state := by
  rcases original with ⟨originalImageBase, originalRead⟩
  rcases candidate with ⟨candidateImageBase, candidateRead⟩
  simp only at imageBase
  subst candidateImageBase
  cases decoded with
  | mk instruction size trailing =>
      cases instruction <;> try rfl
      case x87CompareStack mode destination index pop =>
        cases mode <;> cases destination <;> cases pop <;> rfl
      all_goals
        simp [instructionImageContextIndependent] at independent

/-- A linear exact-byte profile for the context-independent executor fragment.
An undecodable suffix is harmless here: both contexts fail at the same decoder
boundary. Executable coverage remains a separate acceptance obligation. -/
def codeImageContextIndependent : Nat -> Bytes -> Bool
  | 0, _ => true
  | _ + 1, [] => true
  | fuel + 1, bytes =>
      match decodeInstructionExact bytes with
      | none => true
      | some decoded =>
          instructionImageContextIndependent decoded.instruction &&
            codeImageContextIndependent fuel decoded.trailing

theorem executeCodeWithContext_eq_of_imageContextIndependent
    (original candidate : SymbolicImageContext)
    (imports : List PEImport) (fuel undefinedSlot pc : Nat)
    (bytes : Bytes) (state : SymbolicBehavior)
    (imageBase : original.imageBase = candidate.imageBase)
    (independent : codeImageContextIndependent fuel bytes = true) :
    executeCodeWithContext original imports fuel undefinedSlot pc bytes state =
      executeCodeWithContext candidate imports fuel undefinedSlot pc bytes state := by
  induction fuel generalizing undefinedSlot pc bytes state with
  | zero => rfl
  | succ fuel induction =>
      cases bytes with
      | nil => rfl
      | cons head tail =>
          simp only [codeImageContextIndependent] at independent
          generalize decodedEquation :
            decodeInstructionExact (head :: tail) = decoded at independent
          cases decoded with
          | none =>
              simp [executeCodeWithContext, decodedEquation, Bind.bind, Option.bind]
          | some decoded =>
              simp only [Bool.and_eq_true] at independent
              have instructionEqual :=
                executeInstructionWithContext_eq_of_imageContextIndependent
                  original candidate imports pc undefinedSlot decoded state
                  imageBase independent.1
              simp only [executeCodeWithContext, decodedEquation, Bind.bind, Option.bind]
              rw [instructionEqual]
              generalize resultEquation :
                executeInstructionWithContext candidate imports pc undefinedSlot
                  decoded state = result
              cases result with
              | none =>
                  simp only [Bind.bind, Option.bind]
              | some result =>
                  cases result with
                  | next nextState =>
                      simp only [Bind.bind, Option.bind]
                      exact induction (undefinedSlot + 1) (pc + decoded.size)
                        decoded.trailing nextState independent.2
                  | stop finalState =>
                      cases outcomeEquation : finalState.outcome with
                      | none =>
                          simp [Bind.bind, Option.bind, outcomeEquation]
                      | some outcome =>
                          simp only [Bind.bind, Option.bind]
                          rw [outcomeEquation]
                          cases outcome <;> try rfl
                          case jump target =>
                            by_cases fallsThrough :
                                (target == pc + decoded.size) = true
                            · simp only [fallsThrough, if_true]
                              exact induction (undefinedSlot + 1) target
                                decoded.trailing
                                { finalState with outcome := none }
                                independent.2
                            · simp [fallsThrough]

theorem regionBehaviorFromBytesWithContext_eq_of_imageContextIndependent
    (original candidate : SymbolicImageContext)
    (imports : List PEImport) (span : Span) (bytes : Bytes)
    (imageBase : original.imageBase = candidate.imageBase)
    (independent :
      codeImageContextIndependent (bytes.length + 1) bytes = true) :
    regionBehaviorFromBytesWithContext original imports span bytes =
      regionBehaviorFromBytesWithContext candidate imports span bytes := by
  unfold regionBehaviorFromBytesWithContext
  rw [executeCodeWithContext_eq_of_imageContextIndependent
    original candidate imports (bytes.length + 1) 0 span.start bytes
    initialSymbolic imageBase independent]

end StageA.Relational.SemanticsChecker
